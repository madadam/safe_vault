// Copyright 2015 MaidSafe.net limited.
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

use chunk_store::ChunkStore;
use default_chunk_store;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, Data, DataRequest, MessageId, RequestContent, RequestMessage, StructuredData};
use types::{Refresh, RefreshValue};
use vault::RoutingNode;

pub struct StructuredDataManager {
    chunk_store: ChunkStore,
}

impl StructuredDataManager {
    pub fn new() -> StructuredDataManager {
        StructuredDataManager {
            // TODO allow adjustable max_disk_space and return meaningful error rather than panic
            // if the ChunkStore creation fails.
            // See https://maidsafe.atlassian.net/browse/MAID-1370
            chunk_store: default_chunk_store::new().unwrap(),
        }
    }

    pub fn handle_get(&mut self, routing_node: &RoutingNode, request: &RequestMessage) {
        // TODO - handle type_tag from name too
        let (data_name, message_id) = match request.content {
            RequestContent::Get(ref data_request @ DataRequest::StructuredData(_, _), ref message_id) => {
                (data_request.name(), message_id)
            }
            _ => unreachable!("Error in vault demuxing"),
        };

        let data = match self.chunk_store.get(&data_name) {
            Ok(data) => data,
            _ => {
                warn!("Failed to GET data with name {:?}", data_name);
                return;
            }
        };

        let decoded = match deserialise::<StructuredData>(&data) {
            Ok(data) => data,
            Err(_) => {
                warn!("Failed to parse data with name {:?}", data_name);
                return;
            }
        };
        debug!("As {:?} sending data {:?} to {:?}",
               request.dst,
               Data::StructuredData(decoded.clone()),
               request.src);
        let _ = routing_node.send_get_success(request.dst.clone(),
                                              request.src.clone(),
                                              Data::StructuredData(decoded),
                                              message_id.clone());
    }

    pub fn handle_put(&mut self, data: &StructuredData) {
        // SD using PUT for the first copy so the request can pass through MaidManager,
        //    then POST to update and transfer in case of churn
        //       so if the data exists, then the put shall be rejected
        //          if the data does not exist, and the request is not from SDM(i.e. a transfer),
        //              then the post shall be rejected
        //       in addition to above, POST shall check the ownership
        let data_name = data.name();
        if !self.chunk_store.has_chunk(&data_name) {
            if let Ok(serialised_data) = serialise(data) {
                // TODO: error handling
                let _ = self.chunk_store.put(&data_name, &serialised_data);
            } else {
                debug!("Failed to serialise {:?}", data_name);
            }
        } else {
            debug!("Already have SD {:?}", data_name);
        }
    }

    pub fn handle_post(&mut self, request: &RequestMessage) {
        let new_data = match &request.content {
            &RequestContent::Post(Data::StructuredData(ref structured_data), _) => structured_data,
            _ => unreachable!("Error in vault demuxing"),
        };

        // SD using PUT for the first copy so the request can pass through MaidManager,
        //    then POST to update and transfer in case of churn
        //       so if the data exists, then the put shall be rejected
        //          if the data does not exist, and the request is not from SDM(i.e. a transfer),
        //              then the post shall be rejected
        //       in addition to above, POST shall check the ownership
        let serialised_data = match self.chunk_store.get(&new_data.name()) {
            Ok(data) => data,
            _ => {
                warn!("Don't currently hold data for POST at StructuredDataManager: {:?}", request);
                return;
            }
        };

        let _ = deserialise::<StructuredData>(&serialised_data)
                    .ok()
                    .and_then(|mut existing_data| {
                        debug!("StructuredDataManager updating {:?} to {:?}",
                               existing_data,
                               new_data);
                        existing_data.replace_with_other(new_data.clone())
                                     .ok()
                                     .and_then(|()| serialise(&existing_data).ok())
                                     .and_then(|serialised| Some(self.chunk_store.put(&new_data.name(), &serialised)))
                    });
    }

    pub fn handle_refresh(&mut self, structured_data: StructuredData) {
        // TODO: error handling
        let _ = self.chunk_store.delete(&structured_data.name());
        let _ = self.chunk_store.put(&structured_data.name(),
                                     &serialise(&structured_data).unwrap_or(vec![]));
    }

    pub fn handle_churn(&mut self, routing_node: &RoutingNode, churn_event_id: &MessageId) {
        let data_names = self.chunk_store.names();
        for data_name in data_names {
            let serialised_data = match self.chunk_store.get(&data_name) {
                Ok(data) => data,
                _ => continue,
            };

            let structured_data = match deserialise::<StructuredData>(&serialised_data) {
                Ok(parsed_data) => parsed_data,
                Err(_) => continue,
            };

            let src = Authority::NaeManager(data_name.clone());
            let refresh = Refresh {
                id: churn_event_id.clone(),
                name: data_name.clone(),
                value: RefreshValue::StructuredDataManager(structured_data),
            };
            if let Ok(serialised_refresh) = serialise(&refresh) {
                debug!("SD Manager sending refresh for account {:?}",
                       src.get_name());
                let _ = routing_node.send_refresh_request(src, serialised_refresh);
            }
        }
    }
}


/*
#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use lru_time_cache::LruCache;
    use maidsafe_utilities::log;
    use maidsafe_utilities::serialisation::deserialise;
    use rand::random;
    use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, RequestContent, RequestMessage,
                  ResponseContent, ResponseMessage, StructuredData};
    use std::cmp::{max, min, Ordering};
    use std::collections::BTreeSet;
    use time::{Duration, SteadyTime};
    use types::Refreshable;
    use utils::{median, merge, HANDLED, NOT_HANDLED};
    use vault::Routing;
    use xor_name::{XorName, closer_to_target};

    pub struct Environment {
        pub routing: ::vault::Routing,
        pub structured_data_manager: StructuredDataManager,
        pub data_name: XorName,
        pub identifier: XorName,
        pub keys: (::sodiumoxide::crypto::sign::PublicKey,
                   ::sodiumoxide::crypto::sign::SecretKey),
        pub structured_data: ::routing::structured_data::StructuredData,
        pub data: ::routing::data::Data,
        pub us: ::routing::Authority,
        pub client: ::routing::Authority,
        pub maid_manager: ::routing::Authority,
    }

    impl Environment {
        pub fn new() -> Environment {
            log::init(true);
            let routing = ::vault::Routing::new(::std::sync::mpsc::channel().0);
            let identifier = random();
            let keys = ::sodiumoxide::crypto::sign::gen_keypair();
            let structured_data = unwrap_result!(::routing::structured_data::StructuredData::new(0, identifier, 0,
                                     generate_random_vec_u8(1024), vec![keys.0],
                                     vec![], Some(&keys.1)));
            let data_name = structured_data.name();
            Environment {
                routing: routing.clone(),
                structured_data_manager: StructuredDataManager::new(routing),
                data_name: data_name.clone(),
                identifier: identifier,
                keys: keys,
                structured_data: structured_data.clone(),
                data: ::routing::data::Data::StructuredData(structured_data),
                us: Authority::NaeManager(data_name),
                client: Authority::Client(random(),
                                                     ::sodiumoxide::crypto::sign::gen_keypair().0),
                maid_manager: Authority::ClientManager(random()),
            }
        }

        pub fn get_from_chunkstore(&self, data_name: &XorName) -> Option<::routing::structured_data::StructuredData> {
            let data = self.structured_data_manager.chunk_store.get(data_name);
            if data.len() == 0 {
                return None;
            }
            deserialise::<StructuredData>(&data).ok()
        }
    }


    #[test]
    fn handle_put_get() {
        let mut env = Environment::new();
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager.handle_put(&env.us, &env.maid_manager, &env.data));
        assert_eq!(0, env.routing.put_requests_given().len());
        assert_eq!(0, env.routing.put_responses_given().len());

        let request = ::routing::data::DataRequest::StructuredData(env.identifier.clone(), 0);
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager.handle_get(&env.us, &env.client, &request, &None));
        let get_responses = env.routing.get_responses_given();
        assert_eq!(get_responses.len(), 1);
        assert_eq!(get_responses[0].our_authority, env.us);
        assert_eq!(get_responses[0].location, env.client);
        assert_eq!(get_responses[0].data, env.data);
        assert_eq!(get_responses[0].data_request, request);
        assert_eq!(get_responses[0].response_token, None);
    }

    #[test]
    fn handle_post() {
        let mut env = Environment::new();
        // posting to non-existent data
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager.handle_post(&env.us, &env.client, &env.data));
        assert_eq!(None, env.get_from_chunkstore(&env.data_name));

        // PUT the data
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager.handle_put(&env.us, &env.maid_manager, &env.data));
        assert_eq!(env.structured_data,
                   unwrap_option!(env.get_from_chunkstore(&env.data_name), "Failed to get inital data"));

        // incorrect version
        let mut sd_new_bad = unwrap_result!(::routing::structured_data::StructuredData::new(0,
                                                                                              *env.structured_data
                                                                                                  .get_identifier(),
                                                                                              3,
                                                                                              env.structured_data
                                                                                                 .get_data()
                                                                                                 .clone(),
                                                                                              vec![env.keys.0],
                                                                                              vec![],
                                                                                              Some(&env.keys.1)));
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager.handle_post(&env.us,
                                              &env.client,
                                              &::routing::data::Data::StructuredData(sd_new_bad)));
        assert_eq!(env.structured_data,
                   unwrap_option!(env.get_from_chunkstore(&env.data_name), "Failed to get original data."));

        // correct version
        let mut sd_new = unwrap_result!(::routing::structured_data::StructuredData::new(0,
                                                                                          *env.structured_data
                                                                                              .get_identifier(),
                                                                                          1,
                                                                                          env.structured_data
                                                                                             .get_data()
                                                                                             .clone(),
                                                                                          vec![env.keys.0],
                                                                                          vec![],
                                                                                          Some(&env.keys.1)));
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager
                      .handle_post(&env.us,
                                   &env.client,
                                   &::routing::data::Data::StructuredData(sd_new.clone())));
        assert_eq!(sd_new,
                   unwrap_option!(env.get_from_chunkstore(&env.data_name), "Failed to get updated data"));

        // update to a new owner, wrong signature
        let keys2 = ::sodiumoxide::crypto::sign::gen_keypair();
        sd_new_bad = unwrap_result!(::routing::structured_data::StructuredData::new(0,
                                                                                      *env.structured_data
                                                                                          .get_identifier(),
                                                                                      2,
                                                                                      env.structured_data
                                                                                         .get_data()
                                                                                         .clone(),
                                                                                      vec![keys2.0],
                                                                                      vec![env.keys.0],
                                                                                      Some(&keys2.1)));
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager
                      .handle_post(&env.us,
                                   &env.client,
                                   &::routing::data::Data::StructuredData(sd_new_bad.clone())));
        assert_eq!(sd_new,
                   unwrap_option!(env.get_from_chunkstore(&env.data_name), "Failed to get updated data"));

        // update to a new owner, correct signature
        sd_new = unwrap_result!(::routing::structured_data::StructuredData::new(0,
                                                                                  *env.structured_data
                                                                                      .get_identifier(),
                                                                                  2,
                                                                                  env.structured_data
                                                                                     .get_data()
                                                                                     .clone(),
                                                                                  vec![keys2.0],
                                                                                  vec![env.keys.0],
                                                                                  Some(&env.keys.1)));
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager
                      .handle_post(&env.us,
                                   &env.client,
                                   &::routing::data::Data::StructuredData(sd_new.clone())));
        assert_eq!(sd_new,
                   unwrap_option!(env.get_from_chunkstore(&env.data_name), "Failed to get re-updated data"));
    }

    #[test]
    fn handle_churn_and_account_transfer() {
        let mut env = Environment::new();
        let churn_node = random();
        assert_eq!(::utils::HANDLED,
                   env.structured_data_manager.handle_put(&env.us, &env.maid_manager, &env.data));
        env.structured_data_manager.handle_churn(&churn_node);
        let refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 1);
        assert_eq!(refresh_requests[0].type_tag, ACCOUNT_TAG);
        assert_eq!(refresh_requests[0].our_authority, env.us);

        let mut d = ::cbor::Decoder::from_bytes(&refresh_requests[0].content[..]);
        if let Some(sd_account) = d.decode().next().and_then(|result| result.ok()) {
            env.structured_data_manager.handle_account_transfer(sd_account);
        }

        env.structured_data_manager.handle_churn(&churn_node);
        let refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), 2);
        assert_eq!(refresh_requests[0], refresh_requests[1]);
    }
}
*/
