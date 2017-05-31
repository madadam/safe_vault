// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod account;
mod median_accumulator;
#[cfg(all(test, feature = "use-mock-routing"))]
mod tests;

use self::account::Account;
pub use self::account::DEFAULT_MAX_OPS_COUNT;
use self::median_accumulator::MedianAccumulator;
use GROUP_SIZE;
use QUORUM;
use error::InternalError;
use maidsafe_utilities::serialisation;
use routing::{Authority, ClientError, EntryAction, ImmutableData, MessageId, MutableData,
              PermissionSet, RoutingTable, TYPE_TAG_SESSION_PACKET, User, XorName};
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, BTreeSet};
use std::collections::hash_map::Entry;
use std::time::Duration;
use utils::{self, HashMap};
use vault::RoutingNode;

/// The timeout for accumulating refresh messages.
const ACCUMULATOR_TIMEOUT_SECS: u64 = 180;

pub struct MaidManager {
    accounts: HashMap<XorName, Account>,
    data_ops_count_accumulator: MedianAccumulator<MessageId>,
    request_cache: HashMap<MessageId, CachedRequest>,
}

impl MaidManager {
    pub fn new() -> MaidManager {
        MaidManager {
            accounts: HashMap::default(),
            data_ops_count_accumulator:
                MedianAccumulator::new(QUORUM, Duration::from_secs(ACCUMULATOR_TIMEOUT_SECS)),
            request_cache: HashMap::default(),
        }
    }

    pub fn handle_refresh(&mut self,
                          routing_node: &mut RoutingNode,
                          serialised_msg: &[u8],
                          msg_id: MessageId)
                          -> Result<(), InternalError> {
        // `Refresh::Update` and `Refresh::UpdateData` need to be accumulated using
        // a custom algorithm, so `src` is a single node. The other variants don't
        // need custom accumulation, so `src` is a group.

        match serialisation::deserialise::<Refresh>(serialised_msg)? {
            Refresh::Update {
                name,
                data_ops_count,
                keys_ops_count,
                keys,
            } => {
                self.handle_refresh_update(routing_node,
                                           name,
                                           data_ops_count,
                                           keys_ops_count,
                                           keys,
                                           msg_id)
            }
            Refresh::UpdateKeys {
                name,
                ops_count,
                keys,
            } => self.handle_refresh_update_keys(routing_node, name, ops_count, keys),
            Refresh::UpdateData { name, ops_count } => {
                self.handle_refresh_update_data(routing_node, name, ops_count, msg_id)
            }
            Refresh::Delete(name) => self.handle_refresh_delete(name),
        }

        Ok(())
    }

    pub fn handle_get_account_info(&mut self,
                                   routing_node: &mut RoutingNode,
                                   src: Authority<XorName>,
                                   dst: Authority<XorName>,
                                   msg_id: MessageId)
                                   -> Result<(), InternalError> {
        let res = self.get_account(&src, &dst).map(Account::balance);
        routing_node
            .send_get_account_info_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_put_idata(&mut self,
                            routing_node: &mut RoutingNode,
                            src: Authority<XorName>,
                            dst: Authority<XorName>,
                            data: ImmutableData,
                            msg_id: MessageId)
                            -> Result<(), InternalError> {
        if !data.validate_size() {
            routing_node
                .send_put_idata_response(dst, src, Err(ClientError::DataTooLarge), msg_id)?;
            return Ok(());
        }

        if let Err(err) = self.prepare_data_mutation(&src, &dst, AuthPolicy::Key, None) {
            routing_node
                .send_put_idata_response(dst, src, Err(err), msg_id)?;
            return Ok(());
        }

        // Forwarding the request to NAE Manager.
        let fwd_src = dst;
        let fwd_dst = Authority::NaeManager(*data.name());
        trace!("MM forwarding PutIData request to {:?}", fwd_dst);
        routing_node
            .send_put_idata_request(fwd_src, fwd_dst, data, msg_id)?;
        self.insert_into_request_cache(msg_id, src, dst, None);

        Ok(())
    }

    pub fn handle_put_idata_response(&mut self,
                                     routing_node: &mut RoutingNode,
                                     res: Result<(), ClientError>,
                                     msg_id: MessageId)
                                     -> Result<(), InternalError> {
        let CachedRequest { src, dst, .. } =
            self.handle_data_mutation_response(routing_node, msg_id, res.is_ok())?;
        // Send the response back to client
        routing_node
            .send_put_idata_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_put_mdata(&mut self,
                            routing_node: &mut RoutingNode,
                            src: Authority<XorName>,
                            dst: Authority<XorName>,
                            data: MutableData,
                            msg_id: MessageId,
                            requester: sign::PublicKey)
                            -> Result<(), InternalError> {
        if let Err(err) = data.validate() {
            routing_node
                .send_put_mdata_response(dst, src, Err(err), msg_id)?;
            return Ok(());
        }

        let src_name = utils::client_name(&src);
        let dst_name = utils::client_name(&dst);

        if !utils::verify_mdata_owner(&data, &dst_name) {
            routing_node
                .send_put_mdata_response(dst, src, Err(ClientError::InvalidOwners), msg_id)?;
            return Ok(());
        }

        // If the type_tag is `TYPE_TAG_SESSION_PACKET`, the account must not exist, else it must
        // exist.
        if data.tag() == TYPE_TAG_SESSION_PACKET {
            if dst_name != src_name {
                trace!("MM Cannot create account for {:?} as {:?}.", src, dst);
                let err = ClientError::InvalidOperation;
                routing_node
                    .send_put_mdata_response(dst, src, Err(err.clone()), msg_id)?;
                return Ok(());
            }

            match self.accounts.entry(src_name) {
                Entry::Vacant(entry) => {
                    let _ = entry.insert(Account::default());
                }
                Entry::Occupied(_) => {
                    let err = ClientError::AccountExists;
                    trace!("MM Cannot create account for {:?} - it already exists", src);
                    routing_node
                        .send_put_mdata_response(dst, src, Err(err.clone()), msg_id)?;
                    return Ok(());
                }
            }
            info!("Managing {} client accounts.", self.accounts.len());
        }

        if let Err(err) = self.prepare_data_mutation(&src, &dst, AuthPolicy::Key, Some(requester)) {
            trace!("MM PutMData request failed: {:?}", err);
            // Undo the account creation
            if data.tag() == TYPE_TAG_SESSION_PACKET {
                let _ = self.accounts.remove(&src_name);
            }

            routing_node
                .send_put_mdata_response(dst, src, Err(err.clone()), msg_id)?;
            return Ok(());
        }

        let tag = data.tag();

        // Forwarding the request to NAE Manager.
        let fwd_src = dst;
        let fwd_dst = Authority::NaeManager(*data.name());
        trace!("MM forwarding PutMData request to {:?}", fwd_dst);
        routing_node
            .send_put_mdata_request(fwd_src, fwd_dst, data, msg_id, requester)?;

        self.insert_into_request_cache(msg_id, src, dst, Some(tag));

        Ok(())
    }

    pub fn handle_put_mdata_response(&mut self,
                                     routing_node: &mut RoutingNode,
                                     res: Result<(), ClientError>,
                                     msg_id: MessageId)
                                     -> Result<(), InternalError> {
        let CachedRequest { src, dst, tag } =
            self.handle_data_mutation_response(routing_node, msg_id, res.is_ok())?;

        let res = match (tag, res) {
            (_, Ok(())) => Ok(()),
            (Some(TYPE_TAG_SESSION_PACKET), Err(ClientError::DataExists)) => {
                // We wouldn't have forwarded two `Put` requests for the same account, so
                // it must have been created via another client manager.
                let client_name = utils::client_name(&src);
                let _ = self.accounts.remove(&client_name);

                trace!("MM sending delete refresh for account {}", client_name);
                self.send_refresh(routing_node, dst, dst, Refresh::Delete(client_name), msg_id)?;

                Err(ClientError::AccountExists)
            }
            (_, Err(err)) => Err(err),
        };

        // Send response back to client
        routing_node
            .send_put_mdata_response(dst, src, res, msg_id)?;
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_mutate_mdata_entries(&mut self,
                                       routing_node: &mut RoutingNode,
                                       src: Authority<XorName>,
                                       dst: Authority<XorName>,
                                       name: XorName,
                                       tag: u64,
                                       actions: BTreeMap<Vec<u8>, EntryAction>,
                                       msg_id: MessageId,
                                       requester: sign::PublicKey)
                                       -> Result<(), InternalError> {
        if let Err(err) = self.prepare_data_mutation(&src, &dst, AuthPolicy::Key, Some(requester)) {
            routing_node
                .send_mutate_mdata_entries_response(dst, src, Err(err), msg_id)?;
            return Ok(());
        }

        // Forwarding the request to NAE Manager.
        let fwd_src = dst;
        let fwd_dst = Authority::NaeManager(name);
        trace!("MM forwarding MutateMDataEntries request to {:?}", fwd_dst);
        routing_node
            .send_mutate_mdata_entries_request(fwd_src,
                                               fwd_dst,
                                               name,
                                               tag,
                                               actions,
                                               msg_id,
                                               requester)?;

        self.insert_into_request_cache(msg_id, src, dst, Some(tag));

        Ok(())
    }

    pub fn handle_mutate_mdata_entries_response(&mut self,
                                                routing_node: &mut RoutingNode,
                                                res: Result<(), ClientError>,
                                                msg_id: MessageId)
                                                -> Result<(), InternalError> {
        let CachedRequest { src, dst, .. } =
            self.handle_data_mutation_response(routing_node, msg_id, res.is_ok())?;
        routing_node
            .send_mutate_mdata_entries_response(dst, src, res, msg_id)?;
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_set_mdata_user_permissions(&mut self,
                                             routing_node: &mut RoutingNode,
                                             src: Authority<XorName>,
                                             dst: Authority<XorName>,
                                             name: XorName,
                                             tag: u64,
                                             user: User,
                                             permissions: PermissionSet,
                                             version: u64,
                                             msg_id: MessageId,
                                             requester: sign::PublicKey)
                                             -> Result<(), InternalError> {
        if let Err(err) = self.prepare_data_mutation(&src, &dst, AuthPolicy::Key, Some(requester)) {
            routing_node
                .send_set_mdata_user_permissions_response(dst, src, Err(err.clone()), msg_id)?;
            return Ok(());
        }

        // Forwarding the request to NAE Manager.
        let fwd_src = dst;
        let fwd_dst = Authority::NaeManager(name);
        trace!("MM forwarding SetMDataUserPermissions request to {:?}",
               fwd_dst);
        routing_node
            .send_set_mdata_user_permissions_request(fwd_src,
                                                     fwd_dst,
                                                     name,
                                                     tag,
                                                     user,
                                                     permissions,
                                                     version,
                                                     msg_id,
                                                     requester)?;

        self.insert_into_request_cache(msg_id, src, dst, Some(tag));
        Ok(())
    }

    pub fn handle_set_mdata_user_permissions_response(&mut self,
                                                      routing_node: &mut RoutingNode,
                                                      res: Result<(), ClientError>,
                                                      msg_id: MessageId)
                                                      -> Result<(), InternalError> {
        let CachedRequest { src, dst, .. } =
            self.handle_data_mutation_response(routing_node, msg_id, res.is_ok())?;
        routing_node
            .send_set_mdata_user_permissions_response(dst, src, res, msg_id)?;
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_del_mdata_user_permissions(&mut self,
                                             routing_node: &mut RoutingNode,
                                             src: Authority<XorName>,
                                             dst: Authority<XorName>,
                                             name: XorName,
                                             tag: u64,
                                             user: User,
                                             version: u64,
                                             msg_id: MessageId,
                                             requester: sign::PublicKey)
                                             -> Result<(), InternalError> {
        if let Err(err) = self.prepare_data_mutation(&src, &dst, AuthPolicy::Key, Some(requester)) {
            routing_node
                .send_del_mdata_user_permissions_response(dst, src, Err(err.clone()), msg_id)?;
            return Ok(());
        }

        // Forwarding the request to NAE Manager.
        let fwd_src = dst;
        let fwd_dst = Authority::NaeManager(name);
        trace!("MM forwarding DelMDataUserPermissions request to {:?}",
               fwd_dst);
        routing_node
            .send_del_mdata_user_permissions_request(fwd_src,
                                                     fwd_dst,
                                                     name,
                                                     tag,
                                                     user,
                                                     version,
                                                     msg_id,
                                                     requester)?;

        self.insert_into_request_cache(msg_id, src, dst, Some(tag));
        Ok(())
    }

    pub fn handle_del_mdata_user_permissions_response(&mut self,
                                                      routing_node: &mut RoutingNode,
                                                      res: Result<(), ClientError>,
                                                      msg_id: MessageId)
                                                      -> Result<(), InternalError> {
        let CachedRequest { src, dst, .. } =
            self.handle_data_mutation_response(routing_node, msg_id, res.is_ok())?;
        routing_node
            .send_del_mdata_user_permissions_response(dst, src, res, msg_id)?;
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_change_mdata_owner(&mut self,
                                     routing_node: &mut RoutingNode,
                                     src: Authority<XorName>,
                                     dst: Authority<XorName>,
                                     name: XorName,
                                     tag: u64,
                                     new_owners: BTreeSet<sign::PublicKey>,
                                     version: u64,
                                     msg_id: MessageId)
                                     -> Result<(), InternalError> {
        if let Err(err) = self.prepare_data_mutation(&src, &dst, AuthPolicy::Owner, None) {
            routing_node
                .send_change_mdata_owner_response(dst, src, Err(err.clone()), msg_id)?;
            return Ok(());
        }

        // Forwarding the request to NAE Manager.
        let fwd_src = dst;
        let fwd_dst = Authority::NaeManager(name);
        trace!("MM forwarding ChangeMDataOwner request to {:?}", fwd_dst);
        routing_node
            .send_change_mdata_owner_request(fwd_src,
                                             fwd_dst,
                                             name,
                                             tag,
                                             new_owners,
                                             version,
                                             msg_id)?;

        self.insert_into_request_cache(msg_id, src, dst, Some(tag));
        Ok(())
    }

    pub fn handle_change_mdata_owner_response(&mut self,
                                              routing_node: &mut RoutingNode,
                                              res: Result<(), ClientError>,
                                              msg_id: MessageId)
                                              -> Result<(), InternalError> {
        let CachedRequest { src, dst, .. } =
            self.handle_data_mutation_response(routing_node, msg_id, res.is_ok())?;
        routing_node
            .send_change_mdata_owner_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_list_auth_keys_and_version(&mut self,
                                             routing_node: &mut RoutingNode,
                                             src: Authority<XorName>,
                                             dst: Authority<XorName>,
                                             msg_id: MessageId)
                                             -> Result<(), InternalError> {
        let res = self.get_account(&src, &dst)
            .map(|account| (account.keys.clone(), account.keys_ops_count));
        routing_node
            .send_list_auth_keys_and_version_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_ins_auth_key(&mut self,
                               routing_node: &mut RoutingNode,
                               src: Authority<XorName>,
                               dst: Authority<XorName>,
                               key: sign::PublicKey,
                               version: u64,
                               msg_id: MessageId)
                               -> Result<(), InternalError> {
        self.mutate_auth_keys(routing_node, src, dst, KeysOp::Ins, key, version, msg_id)
    }

    pub fn handle_del_auth_key(&mut self,
                               routing_node: &mut RoutingNode,
                               src: Authority<XorName>,
                               dst: Authority<XorName>,
                               key: sign::PublicKey,
                               version: u64,
                               msg_id: MessageId)
                               -> Result<(), InternalError> {
        self.mutate_auth_keys(routing_node, src, dst, KeysOp::Del, key, version, msg_id)
    }

    pub fn handle_node_added(&mut self,
                             routing_node: &mut RoutingNode,
                             node_name: &XorName,
                             routing_table: &RoutingTable<XorName>)
                             -> Result<(), InternalError> {

        // Remove all accounts which we are no longer responsible for.
        let accounts_to_delete: Vec<_> = self.accounts
            .keys()
            .filter(|name| !routing_table.is_closest(*name, GROUP_SIZE))
            .cloned()
            .collect();

        // Remove all requests from the cache that we are no longer responsible for.
        let msg_ids_to_delete: Vec<_> = self.request_cache
            .iter()
            .filter_map(|(msg_id, entry)| if accounts_to_delete.contains(&entry.src.name()) {
                            Some(*msg_id)
                        } else {
                            None
                        })
            .collect();
        for msg_id in msg_ids_to_delete {
            let _ = self.request_cache.remove(&msg_id);
        }

        for name in &accounts_to_delete {
            trace!("No longer a MM for {}", name);
            let _ = self.accounts.remove(name);
        }

        if !accounts_to_delete.is_empty() {
            info!("Managing {} client accounts.", self.accounts.len());
        }

        let msg_id = MessageId::from_added_node(*node_name);
        self.send_refresh_for_all_accounts(routing_node, msg_id)
    }

    pub fn handle_node_lost(&mut self,
                            routing_node: &mut RoutingNode,
                            node_name: &XorName)
                            -> Result<(), InternalError> {
        let msg_id = MessageId::from_lost_node(*node_name);
        self.send_refresh_for_all_accounts(routing_node, msg_id)
    }

    fn get_account(&self,
                   src: &Authority<XorName>,
                   dst: &Authority<XorName>)
                   -> Result<&Account, ClientError> {
        let requestor_name = utils::client_name(src);
        let client_name = utils::client_name(dst);
        if requestor_name != client_name {
            trace!("MM Cannot allow requestor {:?} accessing account {:?}.",
                   src,
                   dst);
            return Err(ClientError::AccessDenied);
        }
        if let Some(account) = self.accounts.get(&client_name) {
            Ok(account)
        } else {
            Err(ClientError::NoSuchAccount)
        }
    }

    fn mutate_auth_keys(&mut self,
                        routing_node: &mut RoutingNode,
                        src: Authority<XorName>,
                        dst: Authority<XorName>,
                        op: KeysOp,
                        key: sign::PublicKey,
                        version: u64,
                        msg_id: MessageId)
                        -> Result<(), InternalError> {
        let res = match self.prepare_auth_keys_mutation(&src, &dst, op, key, version) {
            Ok(keys) => {
                self.send_refresh(routing_node,
                                  dst,
                                  dst,
                                  Refresh::UpdateKeys {
                                      name: utils::client_name(&src),
                                      keys: keys,
                                      ops_count: version,
                                  },
                                  msg_id)?;
                Ok(())
            }
            Err(error) => Err(error),
        };

        match op {
            KeysOp::Ins => {
                routing_node
                    .send_ins_auth_key_response(dst, src, res, msg_id)?;
            }
            KeysOp::Del => {
                routing_node
                    .send_del_auth_key_response(dst, src, res, msg_id)?;
            }
        }

        Ok(())
    }

    fn prepare_auth_keys_mutation(&mut self,
                                  src: &Authority<XorName>,
                                  dst: &Authority<XorName>,
                                  op: KeysOp,
                                  key: sign::PublicKey,
                                  version: u64)
                                  -> Result<BTreeSet<sign::PublicKey>, ClientError> {
        let client_name = utils::client_name(&src);
        let client_manager_name = utils::client_name(&dst);

        if client_name != client_manager_name {
            return Err(ClientError::AccessDenied);
        }

        let account = self.accounts
            .get_mut(&client_manager_name)
            .ok_or(ClientError::NoSuchAccount)?;

        if version != account.keys_ops_count + 1 {
            return Err(ClientError::InvalidSuccessor);
        }

        if !account.has_balance() {
            return Err(ClientError::LowBalance);
        }

        op.apply(&mut account.keys, key)?;
        account.keys_ops_count = version;

        Ok(account.keys.clone())
    }

    fn prepare_data_mutation(&mut self,
                             src: &Authority<XorName>,
                             dst: &Authority<XorName>,
                             policy: AuthPolicy,
                             requester: Option<sign::PublicKey>)
                             -> Result<(), ClientError> {
        let client_manager_name = utils::client_name(dst);

        let account = self.accounts
            .get(&client_manager_name)
            .ok_or(ClientError::NoSuchAccount)?;
        let client_key = utils::client_key(src);
        let client_name = utils::client_name_from_key(client_key);

        let allowed = client_name == client_manager_name ||
                      if AuthPolicy::Key == policy {
                          account.keys.contains(client_key)
                      } else {
                          false
                      };

        if !allowed {
            return Err(ClientError::AccessDenied);
        }

        if let Some(requester) = requester {
            if requester != *client_key {
                return Err(ClientError::AccessDenied);
            }
        }

        if !account.has_balance() {
            return Err(ClientError::LowBalance);
        }

        Ok(())
    }

    fn handle_data_mutation_response(&mut self,
                                     routing_node: &mut RoutingNode,
                                     msg_id: MessageId,
                                     success: bool)
                                     -> Result<CachedRequest, InternalError> {
        let req = self.remove_from_request_cache(&msg_id)?;
        let client_name = utils::client_name(&req.dst);

        let ops_count = {
            let account = self.accounts
                .get_mut(&client_name)
                .ok_or(InternalError::NoSuchAccount)?;

            if success {
                account.data_ops_count = account.data_ops_count.saturating_add(1);
            }

            account.data_ops_count
        };

        // Source authority is a single node because we are doing custom accumulation.
        let refresh_src = Authority::ManagedNode(routing_node.name()?);
        let refresh_dst = req.dst;
        self.send_refresh(routing_node,
                          refresh_src,
                          refresh_dst,
                          Refresh::UpdateData {
                              name: client_name,
                              ops_count: ops_count,
                          },
                          msg_id)?;

        Ok(req)
    }

    fn send_refresh(&self,
                    routing_node: &mut RoutingNode,
                    src: Authority<XorName>,
                    dst: Authority<XorName>,
                    refresh: Refresh,
                    msg_id: MessageId)
                    -> Result<(), InternalError> {
        let payload = serialisation::serialise(&refresh)?;
        routing_node
            .send_refresh_request(src, dst, payload, msg_id)?;
        Ok(())
    }

    fn send_refresh_for_all_accounts(&mut self,
                                     routing_node: &mut RoutingNode,
                                     msg_id: MessageId)
                                     -> Result<(), InternalError> {
        // We need to send the refresh as a single node (not group) to trigger the
        // custom accumulation,
        let src = Authority::ManagedNode(routing_node.name()?);

        for (name, account) in &self.accounts {
            let dst = Authority::ClientManager(*name);

            self.send_refresh(routing_node,
                              src,
                              dst,
                              Refresh::update(name, account),
                              msg_id)?;
        }

        Ok(())
    }

    // `src` is a node - use custom accumulation.
    fn handle_refresh_update(&mut self,
                             routing_node: &mut RoutingNode,
                             account_name: XorName,
                             data_ops_count: u64,
                             keys_ops_count: u64,
                             keys: BTreeSet<sign::PublicKey>,
                             msg_id: MessageId) {
        if let Some(ops_count) = self.data_ops_count_accumulator
               .add(msg_id, data_ops_count) {
            if let Some(account) = self.fetch_account(routing_node, account_name) {
                if account.data_ops_count < ops_count {
                    account.data_ops_count = ops_count;
                }

                if account.keys_ops_count < keys_ops_count {
                    account.keys = keys;
                    account.keys_ops_count = keys_ops_count;
                }
            }
        }
    }

    // `src` is a node - use custom accumulation.
    fn handle_refresh_update_data(&mut self,
                                  routing_node: &RoutingNode,
                                  account_name: XorName,
                                  ops_count: u64,
                                  msg_id: MessageId) {
        if let Some(ops_count) = self.data_ops_count_accumulator.add(msg_id, ops_count) {
            if let Some(account) = self.fetch_account(routing_node, account_name) {
                if account.data_ops_count < ops_count {
                    account.data_ops_count = ops_count;
                }
            }
        }
    }

    // `src` is a group - already accumulated.
    fn handle_refresh_update_keys(&mut self,
                                  routing_node: &RoutingNode,
                                  account_name: XorName,
                                  ops_count: u64,
                                  keys: BTreeSet<sign::PublicKey>) {
        if let Some(account) = self.fetch_account(routing_node, account_name) {
            if account.keys_ops_count < ops_count {
                account.keys = keys;
                account.keys_ops_count = ops_count;
            }
        }
    }

    // `src` is a group - already accumulated.
    fn handle_refresh_delete(&mut self, account_name: XorName) {
        let _ = self.accounts.remove(&account_name);
        info!("Managing {} client accounts.", self.accounts.len());
    }

    fn insert_into_request_cache(&mut self,
                                 msg_id: MessageId,
                                 src: Authority<XorName>,
                                 dst: Authority<XorName>,
                                 tag: Option<u64>) {
        if let Some(prev) = self.request_cache
               .insert(msg_id, CachedRequest { src, dst, tag }) {
            error!("Overwrote existing cached request with {:?} from {:?} to {:?}",
                   msg_id,
                   prev.src,
                   prev.dst);
        }
    }

    fn remove_from_request_cache(&mut self,
                                 msg_id: &MessageId)
                                 -> Result<CachedRequest, InternalError> {
        self.request_cache
            .remove(msg_id)
            .ok_or_else(move || InternalError::FailedToFindCachedRequest(*msg_id))
    }

    fn fetch_account(&mut self,
                     routing_node: &RoutingNode,
                     account_name: XorName)
                     -> Option<&mut Account> {
        if routing_node
               .close_group(account_name, GROUP_SIZE)
               .is_none() {
            return None;
        }

        let accounts_len = self.accounts.len();
        let account = self.accounts
            .entry(account_name)
            .or_insert_with(|| {
                                info!("Managing {} client accounts.", accounts_len + 1);
                                Account::default()
                            });

        Some(account)
    }
}

#[cfg(feature = "use-mock-crust")]
impl MaidManager {
    pub fn get_mutation_count(&self, client_name: &XorName) -> Option<u64> {
        self.accounts
            .get(client_name)
            .map(|account| account.data_ops_count)
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
enum Refresh {
    Update {
        name: XorName,
        data_ops_count: u64,
        keys_ops_count: u64,
        keys: BTreeSet<sign::PublicKey>,
    },
    UpdateKeys {
        name: XorName,
        ops_count: u64,
        keys: BTreeSet<sign::PublicKey>,
    },
    UpdateData { name: XorName, ops_count: u64 },
    Delete(XorName),
}

impl Refresh {
    fn update(name: &XorName, account: &Account) -> Self {
        Refresh::Update {
            name: *name,
            data_ops_count: account.data_ops_count,
            keys_ops_count: account.keys_ops_count,
            keys: account.keys.clone(),
        }
    }
}

#[derive(Clone, Copy)]
enum KeysOp {
    Ins,
    Del,
}

impl KeysOp {
    fn apply(self,
             keys: &mut BTreeSet<sign::PublicKey>,
             key: sign::PublicKey)
             -> Result<(), ClientError> {
        match self {
            KeysOp::Ins => {
                // TODO: consider returning error when the key already exists.
                // (would probably require new `ClientError` variant)
                let _ = keys.insert(key);
                Ok(())
            }
            KeysOp::Del => {
                if keys.remove(&key) {
                    Ok(())
                } else {
                    Err(ClientError::NoSuchKey)
                }
            }
        }
    }
}

#[derive(PartialEq)]
enum AuthPolicy {
    // Operation allowed only for the account owner.
    Owner,
    // Operation allowed for any authorised client.
    Key,
}

struct CachedRequest {
    src: Authority<XorName>,
    dst: Authority<XorName>,
    tag: Option<u64>,
}
