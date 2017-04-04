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

use super::*;
use super::account::DEFAULT_ACCOUNT_SIZE;
use rand;
use routing::{AccountInfo, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES, MAX_MUTABLE_DATA_ENTRIES,
              MAX_MUTABLE_DATA_SIZE_IN_BYTES, Request, Response, Value};
use test_utils;

const TEST_TAG: u64 = 12345678;

#[test]
fn account_basics() {
    let (src, client_key) = test_utils::gen_client_authority();
    let dst = test_utils::gen_client_manager_authority(client_key);

    let mut node = RoutingNode::new();
    let mut mm = MaidManager::new();

    // Retrieving account info for non-existintg account fails.
    let res = get_account_info(&mut node, &mut mm, src, dst);
    assert_match!(res, Err(ClientError::NoSuchAccount));

    // Create the account by issuing a PutMData with a special tag.
    create_account(&mut node, &mut mm, src, dst);

    // Now retrieving account info succeeds.
    let account_info = unwrap!(get_account_info(&mut node, &mut mm, src, dst));

    assert_eq!(account_info.mutations_done, 1);
    assert_eq!(account_info.mutations_available, DEFAULT_ACCOUNT_SIZE - 1);
}

#[test]
fn idata_basics() {
    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    let mut node = RoutingNode::new();
    let mut mm = MaidManager::new();

    // Create account and retrieve the current account info.
    create_account(&mut node, &mut mm, client, client_manager);
    let account_info_0 = unwrap!(get_account_info(&mut node, &mut mm, client, client_manager));

    // Put immutable data.
    let data = test_utils::gen_immutable_data(10, &mut rand::thread_rng());
    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_idata(&mut node, client, client_manager, data.clone(), msg_id));

    // Verify it gets forwarded to the NAE manager.
    let message = unwrap!(node.sent_requests.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, Authority::NaeManager(*data.name()));
    assert_match!(message.request,
                  Request::PutIData { data: request_data, .. } => {
                      assert_eq!(request_data, data);
                  });

    // Simulate receiving the response from the NAE manager and verify it gets
    // forwarded to the client.
    unwrap!(mm.handle_put_idata_response(&mut node, Ok(()), msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, client);
    assert_match!(message.response, Response::PutIData { res: Ok(()), .. });

    // Verify the mutation was accounted for.
    let account_info_1 = unwrap!(get_account_info(&mut node, &mut mm, client, client_manager));
    assert_eq!(account_info_1.mutations_done,
               account_info_0.mutations_done + 1);
    assert_eq!(account_info_1.mutations_available,
               account_info_0.mutations_available - 1);
}

#[test]
fn mdata_basics() {
    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    let mut node = RoutingNode::new();
    let mut mm = MaidManager::new();

    // Create account and retrieve the current account info.
    create_account(&mut node, &mut mm, client, client_manager);
    let account_info_0 = unwrap!(get_account_info(&mut node, &mut mm, client, client_manager));

    // Put initial mutable data
    let tag = rand::random();
    let data = test_utils::gen_mutable_data(tag, 0, client_key, &mut rand::thread_rng());

    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_mdata(&mut node,
                                client,
                                client_manager,
                                data.clone(),
                                msg_id,
                                client_key));

    // Verify it got forwarded to the NAE manager.
    let message = unwrap!(node.sent_requests.remove(&msg_id));

    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, Authority::NaeManager(*data.name()));

    assert_match!(
            message.request,
            Request::PutMData { data: request_data, .. } => {
                assert_eq!(request_data, data);
            });

    // Simulate receiving the response from the NAE manager and verify it gets
    // forwarded to the client.
    unwrap!(mm.handle_put_mdata_response(&mut node, Ok(()), msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, client);
    assert_match!(message.response, Response::PutMData { res: Ok(()), .. });

    // Verify the mutation was accounted for.
    let account_info_1 = unwrap!(get_account_info(&mut node, &mut mm, client, client_manager));
    assert_eq!(account_info_1.mutations_done,
               account_info_0.mutations_done + 1);
    assert_eq!(account_info_1.mutations_available,
               account_info_0.mutations_available - 1);

    // The node should send refresh request too, but we don't care about that
    // in this test.
    node.sent_requests.clear();

    // Mutate the data.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_mutate_mdata_entries(&mut node,
                                           client,
                                           client_manager,
                                           *data.name(),
                                           data.tag(),
                                           Default::default(),
                                           msg_id,
                                           client_key));

    // Verify it got forwarded to the NAE manager.
    let message = unwrap!(node.sent_requests.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, Authority::NaeManager(*data.name()));
    assert_match!(message.request, Request::MutateMDataEntries { .. });

    // Simulate receiving the response from the NAE manager and verify it gets
    // forwarded to the client.
    unwrap!(mm.handle_mutate_mdata_entries_response(&mut node, Ok(()), msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, client);
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    // Verify the mutation was accounted for.
    let account_info_2 = unwrap!(get_account_info(&mut node, &mut mm, client, client_manager));
    assert_eq!(account_info_2.mutations_done,
               account_info_0.mutations_done + 2);
    assert_eq!(account_info_2.mutations_available,
               account_info_0.mutations_available - 2);
}

#[test]
fn mdata_permissions_and_owners() {
    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    let mut node = RoutingNode::new();
    let mut mm = MaidManager::new();

    create_account(&mut node, &mut mm, client, client_manager);

    // Put initial mutable data
    let data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key, &mut rand::thread_rng());
    let data_name = *data.name();
    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_mdata(&mut node,
                                client,
                                client_manager,
                                data,
                                msg_id,
                                client_key));

    let (app, app_key) = test_utils::gen_client_authority();

    // Set user permissions
    let msg_id = MessageId::new();
    unwrap!(mm.handle_set_mdata_user_permissions(&mut node,
                                                 client,
                                                 client_manager,
                                                 data_name,
                                                 TEST_TAG,
                                                 User::Key(app_key),
                                                 PermissionSet::new(),
                                                 3,
                                                 msg_id,
                                                 client_key));

    // Verify it got forwarded to the NAE manager.
    let message = unwrap!(node.sent_requests.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, Authority::NaeManager(data_name));
    assert_match!(message.request, Request::SetMDataUserPermissions { .. });

    // Simulate receiving the response from the NAE manager and verify it gets
    // forwarded to the client.
    unwrap!(mm.handle_set_mdata_user_permissions_response(&mut node, Ok(()), msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, client);
    assert_match!(message.response, Response::SetMDataUserPermissions { res: Ok(()), .. });

    node.sent_requests.clear();

    // Delete user permissions
    let msg_id = MessageId::new();
    unwrap!(mm.handle_del_mdata_user_permissions(&mut node,
                                                 client,
                                                 client_manager,
                                                 data_name,
                                                 TEST_TAG,
                                                 User::Key(app_key),
                                                 4,
                                                 msg_id,
                                                 client_key));

    // Verify it got forwarded to the NAE manager.
    let message = unwrap!(node.sent_requests.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, Authority::NaeManager(data_name));
    assert_match!(message.request, Request::DelMDataUserPermissions { .. });

    // Simulate receiving the response from the NAE manager and verify it gets
    // forwarded to the client.
    unwrap!(mm.handle_del_mdata_user_permissions_response(&mut node, Ok(()), msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, client);
    assert_match!(message.response, Response::DelMDataUserPermissions { res: Ok(()), .. });

    node.sent_requests.clear();

    // Attempt to change owner by unauthorised app fails.
    let mut new_owners = BTreeSet::new();
    let _ = new_owners.insert(app_key);
    let msg_id = MessageId::new();
    unwrap!(mm.handle_change_mdata_owner(&mut node,
                                         app,
                                         client_manager,
                                         data_name,
                                         TEST_TAG,
                                         new_owners.clone(),
                                         5,
                                         msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response,
                  Response::ChangeMDataOwner { res: Err(ClientError::AccessDenied), .. });

    // Attempt to change owner even by authorised app fails.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_ins_auth_key(&mut node, client, client_manager, app_key, 5, msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response, Response::InsAuthKey { res: Ok(()), .. });

    let msg_id = MessageId::new();
    unwrap!(mm.handle_change_mdata_owner(&mut node,
                                         app,
                                         client_manager,
                                         data_name,
                                         TEST_TAG,
                                         new_owners.clone(),
                                         5,
                                         msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response,
                  Response::ChangeMDataOwner { res: Err(ClientError::AccessDenied), .. });

    // Only the client can change owner
    let msg_id = MessageId::new();
    unwrap!(mm.handle_change_mdata_owner(&mut node,
                                         client,
                                         client_manager,
                                         data_name,
                                         TEST_TAG,
                                         new_owners,
                                         5,
                                         msg_id));

    // Verify it got forwarded to the NAE manager.
    let message = unwrap!(node.sent_requests.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, Authority::NaeManager(data_name));
    assert_match!(message.request, Request::ChangeMDataOwner { .. });

    // Simulate receiving the response from the NAE manager and verify it gets
    // forwarded to the client.
    unwrap!(mm.handle_change_mdata_owner_response(&mut node, Ok(()), msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, client);
    assert_match!(message.response, Response::ChangeMDataOwner { res: Ok(()), .. });
}

#[test]
fn auth_keys() {
    let (owner_client, owner_key) = test_utils::gen_client_authority();
    let owner_client_manager = test_utils::gen_client_manager_authority(owner_key);
    let (_, app_key) = test_utils::gen_client_authority();

    let mut node = RoutingNode::new();
    let mut mm = MaidManager::new();

    // Create owner account
    create_account(&mut node, &mut mm, owner_client, owner_client_manager);

    // Retrieve initial auth keys - should be empty. The version should be 1,
    // because the account mutation counter has already been updated - to
    // reflect the account creation itself.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_list_auth_keys_and_version(&mut node,
                                                     owner_client,
                                                     owner_client_manager,
                                                     msg_id));
    let (auth_keys, version) = assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::ListAuthKeysAndVersion { res: Ok(ok), .. } => ok);

    assert!(auth_keys.is_empty());
    assert_eq!(version, 1);

    // Attempt to insert new auth key with incorrect version fails.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_ins_auth_key(&mut node,
                                       owner_client,
                                       owner_client_manager,
                                       app_key,
                                       1,
                                       msg_id));

    assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::InsAuthKey { res: Err(ClientError::InvalidSuccessor), .. });

    // Attempt to insert new auth key by non-owner fails.
    let (evil_client, _) = test_utils::gen_client_authority();
    let msg_id = MessageId::new();
    unwrap!(mm.handle_ins_auth_key(&mut node,
                                       evil_client,
                                       owner_client_manager,
                                       app_key,
                                       2,
                                       msg_id));

    assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::InsAuthKey { res: Err(ClientError::AccessDenied), .. });

    // Insert the auth key with proper version bump.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_ins_auth_key(&mut node,
                                       owner_client,
                                       owner_client_manager,
                                       app_key,
                                       2,
                                       msg_id));

    assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::InsAuthKey { res: Ok(()), .. });

    // Retrieve the auth keys again - should contain one element and have
    // bumped version.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_list_auth_keys_and_version(&mut node,
                                                     owner_client,
                                                     owner_client_manager,
                                                     msg_id));
    let (auth_keys, version) = assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::ListAuthKeysAndVersion { res: Ok(ok), .. } => ok);

    assert_eq!(auth_keys.len(), 1);
    assert!(auth_keys.contains(&app_key));
    assert_eq!(version, 2);
}

#[test]
fn mutation_authorisation() {
    let (owner_client, owner_key) = test_utils::gen_client_authority();
    let owner_client_manager = test_utils::gen_client_manager_authority(owner_key);
    let (app_client, app_key) = test_utils::gen_client_authority();

    let mut node = RoutingNode::new();
    let mut mm = MaidManager::new();

    // Create owner account
    create_account(&mut node, &mut mm, owner_client, owner_client_manager);

    let tag = rand::random();
    let data = test_utils::gen_mutable_data(tag, 0, owner_key, &mut rand::thread_rng());
    let data_name = *data.name();

    // Attempt to put by unauthorised client fails.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_mdata(&mut node,
                                app_client,
                                owner_client_manager,
                                data.clone(),
                                msg_id,
                                app_key));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response,
                  Response::PutMData { res: Err(ClientError::AccessDenied), ..});

    // Put by authorised client is ok.
    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_mdata(&mut node,
                                owner_client,
                                owner_client_manager,
                                data,
                                msg_id,
                                owner_key));

    // Attemp to mutate by unauthorised client fails.
    let msg_id = MessageId::new();
    let _ = mm.handle_mutate_mdata_entries(&mut node,
                                           app_client,
                                           owner_client_manager,
                                           data_name,
                                           tag,
                                           Default::default(),
                                           msg_id,
                                           app_key);
    assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::MutateMDataEntries { res: Err(ClientError::AccessDenied), .. });

    // Mutation by the owner succeeds.
    let msg_id = MessageId::new();
    let _ = mm.handle_mutate_mdata_entries(&mut node,
                                           owner_client,
                                           owner_client_manager,
                                           data_name,
                                           tag,
                                           Default::default(),
                                           msg_id,
                                           owner_key);
    // Note: No response sent here means all is good (MM sends response to
    // MutateMDataEntries request only in case of error).
    assert!(!node.sent_responses.contains_key(&msg_id));

    // Authorise the app.
    let msg_id = MessageId::new();
    let _ = mm.handle_ins_auth_key(&mut node,
                                   owner_client,
                                   owner_client_manager,
                                   app_key,
                                   4, // current version is 3, due to the above mutations.
                                   msg_id);
    assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::InsAuthKey { res: Ok(()), .. });

    // Mutation by authorised app now succeeds.
    let msg_id = MessageId::new();
    let _ = mm.handle_mutate_mdata_entries(&mut node,
                                           app_client,
                                           owner_client_manager,
                                           data_name,
                                           tag,
                                           Default::default(),
                                           msg_id,
                                           app_key);
    assert!(!node.sent_responses.contains_key(&msg_id));

    // Simulate receiving mutation response from the nae manager and verify it
    // gets forwarded to the app.
    unwrap!(mm.handle_mutate_mdata_entries_response(&mut node, Ok(()), msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_eq!(message.src, owner_client_manager);
    assert_eq!(message.dst, app_client);
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    // Attempt to mutate by requester that doesn't match the source client
    // key fails.
    let msg_id = MessageId::new();
    let _ = mm.handle_mutate_mdata_entries(&mut node,
                                           app_client,
                                           owner_client_manager,
                                           data_name,
                                           tag,
                                           Default::default(),
                                           msg_id,
                                           owner_key);
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(
            message.response,
            Response::MutateMDataEntries { res: Err(ClientError::AccessDenied), .. });
}

#[test]
fn account_replication_during_churn() {
    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    let mut old_node = RoutingNode::new();
    let mut old_mm = MaidManager::new();

    create_account(&mut old_node, &mut old_mm, client, client_manager);

    let mut new_node = RoutingNode::new();
    let mut new_mm = MaidManager::new();
    let new_node_name = unwrap!(new_node.name());

    // The new node doesn't have the account initially.
    let res = get_account_info(&mut new_node, &mut new_mm, client, client_manager);
    assert_match!(res, Err(ClientError::NoSuchAccount));

    // Simulate the new node joining the group.
    old_node.add_to_routing_table(new_node_name);
    new_node.add_to_routing_table(unwrap!(old_node.name()));

    let rt = old_node.routing_table().clone();
    old_mm.handle_node_added(&mut old_node, &new_node_name, &rt);

    // The old node sends refresh request to the client manager of each account it holds.
    let msg_id = MessageId::from_added_node(new_node_name);
    let message = unwrap!(old_node.sent_requests.remove(&msg_id));
    assert_eq!(message.src, client_manager);
    assert_eq!(message.dst, client_manager);
    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);

    // After new node receives the refresh, it gets the account too.
    unwrap!(new_mm.handle_refresh(&mut new_node, &payload));
    assert!(get_account_info(&mut new_node, &mut new_mm, client, client_manager).is_ok());
}

#[test]
fn limits() {
    let mut rng = rand::thread_rng();

    let mut node = RoutingNode::new();
    let mut mm = MaidManager::new();

    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    // Attempt to put oversized immutable data fails.
    let bad_data = test_utils::gen_immutable_data(MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as usize + 1,
                                                  &mut rng);
    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_idata(&mut node,
                                client,
                                client_manager,
                                bad_data,
                                msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response,
                  Response::PutIData { res: Err(ClientError::DataTooLarge), .. });


    // Attempt to put mutable data with too many entries fails.
    let mut bad_data = test_utils::gen_mutable_data(TEST_TAG,
                                                    MAX_MUTABLE_DATA_ENTRIES as usize,
                                                    client_key,
                                                    &mut rng);
    while bad_data.keys().len() <= MAX_MUTABLE_DATA_ENTRIES as usize {
        let key = test_utils::gen_vec(10, &mut rng);
        let content = test_utils::gen_vec(10, &mut rng);
        let _ = bad_data.mutate_entry_without_validation(key,
                                                         Value {
                                                             content: content,
                                                             entry_version: 0,
                                                         });
    }

    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_mdata(&mut node,
                                client,
                                client_manager,
                                bad_data,
                                msg_id,
                                client_key));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response,
                  Response::PutMData { res: Err(ClientError::TooManyEntries), .. });

    // Attempt to put oversized mutable data fails.
    let mut bad_data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key, &mut rng);
    let key = test_utils::gen_vec(10, &mut rng);
    let content = test_utils::gen_vec(MAX_MUTABLE_DATA_SIZE_IN_BYTES as usize + 1, &mut rng);
    assert!(bad_data.mutate_entry_without_validation(key,
                                                     Value {
                                                        content: content,
                                                        entry_version: 0
                                                     }));

    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_mdata(&mut node,
                                client,
                                client_manager,
                                bad_data,
                                msg_id,
                                client_key));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response,
                  Response::PutMData { res: Err(ClientError::DataTooLarge), .. });
}

fn create_account(node: &mut RoutingNode,
                  mm: &mut MaidManager,
                  src: Authority<XorName>,
                  dst: Authority<XorName>) {
    let client_key = assert_match!(src, Authority::Client { client_key, .. } => client_key);
    let account_packet = test_utils::gen_mutable_data(TYPE_TAG_SESSION_PACKET,
                                                      0,
                                                      client_key,
                                                      &mut rand::thread_rng());
    let msg_id = MessageId::new();
    unwrap!(mm.handle_put_mdata(node, src, dst, account_packet, msg_id, client_key));
}

fn get_account_info(node: &mut RoutingNode,
                    mm: &mut MaidManager,
                    src: Authority<XorName>,
                    dst: Authority<XorName>)
                    -> Result<AccountInfo, ClientError> {
    let msg_id = MessageId::new();
    unwrap!(mm.handle_get_account_info(node, src, dst, msg_id));

    assert_match!(
            unwrap!(node.sent_responses.remove(&msg_id)).response,
            Response::GetAccountInfo { res, .. } => res)
}