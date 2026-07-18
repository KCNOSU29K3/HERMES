use crate::{
    datatypes::{DBData, DataServer, DbWrite, DecodedMessage, ProtocolData, UserInterface},
    errors::ProtocolError,
};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::datatypes::{Addr, CryptoProtocol, DbAccessProtocol, DbQuery, RequestID};

pub const MIN_KEYS: usize = 64;

struct DbResponseHandler {
    and_then: Box<dyn FnMut(Vec<DBData>) -> Result<(), ProtocolError>>,
    timeout: Box<dyn Fn() -> Result<(), ProtocolError>>,
}

impl DbResponseHandler {
    pub fn new(
        and_then: Box<dyn FnMut(Vec<DBData>) -> Result<(), ProtocolError>>,
        timeout: Box<dyn Fn() -> Result<(), ProtocolError>>,
    ) -> Self {
        Self { and_then, timeout }
    }
}

pub struct HermesProtocol {
    user: Rc<Addr>,
    request_mapper: HashMap<RequestID, DbResponseHandler>,
    database_protocol: Box<dyn DbAccessProtocol>,
    data_serving_protocol: Rc<dyn DataServer>,
    interface_protocol: Box<dyn UserInterface>,
    conversation_protocol: Rc<RefCell<dyn CryptoProtocol>>,
}

// public facing utilities
impl HermesProtocol {
    pub fn new(
        whoami: Addr,
        conversation_protocol: Rc<RefCell<dyn CryptoProtocol>>,
        database_protocol: Box<dyn DbAccessProtocol>,
        data_serving_protocol: Rc<dyn DataServer>,
        interface_protocol: Box<dyn UserInterface>,
    ) -> Self {
        Self {
            user: Rc::new(whoami),
            request_mapper: HashMap::new(),
            conversation_protocol,
            database_protocol,
            data_serving_protocol,
            interface_protocol,
        }
    }
}

// networking implementations.
// Functions for handling inbound data and resolving queued DB requests.
impl HermesProtocol {
    pub fn inbound_data(&mut self, data: ProtocolData) {
        match data {
            ProtocolData::InitiatingBundle { who, data } => {
                _ = self
                    .conversation_protocol
                    .borrow_mut()
                    .resolve_conversation_request(&who, &data)
                    .map(|_| {
                        let current_keys = self.conversation_protocol.borrow().check_keys();
                        if current_keys < MIN_KEYS {
                            let keys = self
                                .conversation_protocol
                                .borrow_mut()
                                .generate_keys(MIN_KEYS - current_keys);
                            for key in keys {
                                self.database_protocol
                                    .write_db_or_cache(DbWrite::Prekey(key));
                            }
                        }
                    })
                    .map_err(|err| {
                        self.interface_protocol.protocol_error(&err);
                    });
            }
            ProtocolData::CryptMessage { .. } => {
                _ = data
                    .self_as_crypt_msg()
                    .and_then(|data| {
                        self.conversation_protocol
                            .borrow_mut()
                            .decrypt_message(data)
                    })
                    .map(|data| {
                        self.interface_protocol.new_message(data);
                    })
                    .map_err(|err| {
                        self.interface_protocol.protocol_error(&err);
                    });
            }
            ProtocolData::Null => {}
        }
    }

    pub fn resolve(&mut self, query_id: RequestID, data: Vec<DBData>, timed_out: bool) {
        let result = self.resolve_internal(query_id, data, timed_out);
        if let Err(err) = result {
            self.interface_protocol.protocol_error(&err);
        }
    }
}

// User oriented functions
// Public functions for creating new messages and conversations.
impl HermesProtocol {
    pub fn create_new_conversation(&mut self, target: Addr) {
        let query_id = self
            .database_protocol
            .query_db(DbQuery::IdentityKey)
            .add(DbQuery::Prekey)
            .add(DbQuery::Otk)
            .execute();

        let user = self.user.clone();
        let conversation_protocol = self.conversation_protocol.clone();
        let data_serving_protocol = self.data_serving_protocol.clone();

        let response_handler = Box::new(move |data: Vec<DBData>| {
            let DBData::IdentityKey(key) = data[0] else {
                return Err(ProtocolError::FailedRequest {
                    reason: "Expected identity key but got something else.".into(),
                });
            };
            let DBData::Prekey(ref bundle) = data[1] else {
                return Err(ProtocolError::FailedRequest {
                    reason: "Expected prekey bundle but got something else.".into(),
                });
            };

            let DBData::Otk(ref otk) = data[2] else {
                return Err(ProtocolError::FailedRequest {
                    reason: "Expected Otk but got something else.".into(),
                });
            };

            let initiating_bundle = conversation_protocol
                .borrow_mut()
                .new_conversation(&target, key, bundle, otk)?;

            data_serving_protocol.send_else_cache_data(ProtocolData::InitiatingBundle {
                who: (*user).clone(),
                data: initiating_bundle,
            });
            Ok(())
        });
        let timeout_handler = Box::new(move || {
            Err(ProtocolError::FailedRequest {
                reason: "Failed to connect to database. Could not pull key components.".into(),
            })
        });

        self.request_mapper.insert(
            query_id,
            DbResponseHandler::new(response_handler, timeout_handler),
        );
    }

    pub fn send_message(&mut self, who: &Addr, message: DecodedMessage) -> Result<(), ProtocolError> {
        if !self.conversation_protocol.borrow().conversation_exists(who) {
            return Err(ProtocolError::UnknownUser {
                user: who.clone(),
                reason: "No active conversation with that ID.".into(),
            });
        }
        let message = self
            .conversation_protocol
            .borrow_mut()
            .send_message(who, message)?
            .self_as_protocol_data();
        self.data_serving_protocol.send_else_cache_data(message);
        Ok(())
    }
}

// private functions
impl HermesProtocol {
    fn resolve_internal(
        &mut self,
        query_id: RequestID,
        data: Vec<DBData>,
        timed_out: bool,
    ) -> Result<(), ProtocolError> {
        if let Some(handler) = self.request_mapper.get_mut(&query_id) {
            if timed_out {
                (handler.timeout)()?;
                Ok(())
            } else {
                (handler.and_then)(data)
            }
        } else {
            Err(ProtocolError::UnknownRequest {
                request_id: query_id,
            })
        }
    }
}
