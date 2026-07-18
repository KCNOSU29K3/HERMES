use hcrypt::double_ratchet::{DoubleRatchetMessage, InitiatingBundle};
use serde::{Deserialize, Serialize};

use crate::{errors::ProtocolError};
use hcrypt::{
    double_ratchet::{DoubleRatchetProtocolImplementor, PrekeyBundle},
    key::PublicKey,
};
use uuid::Uuid;

/// The output type of whichever Serde-compatible Serialization
/// protocol is in use.
/// The Owned version of the DataReprType. Must implement asRef for DataReprType.
/// The agreed upon Type that is used to uniquely identify users.
pub type Addr = String;
pub const SERVER_ADDR: &str = "HOME";
/// The agreed upon Type that is used to identify requests that are
/// being processed.
pub type RequestID = Uuid;

#[derive(Debug)]
pub struct CryptMessage {
    pub payload: DoubleRatchetMessage,
    pub datatype: MessageType,
    pub sender: Addr,
}
 
pub struct DecodedMessage {
    pub payload: Vec<u8>,
    pub datatype: MessageType,
    pub sender: Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Text,
    Image,
}

#[derive(Debug)]
pub enum DbQuery {
    IdentityKey,
    Prekey,
    Otk,
}

#[derive(PartialEq, Eq)]
pub enum QueryState {
    Completed,
    PartialCompleted,
    Timeout,
}

#[derive(Serialize, Deserialize)]
pub enum ProtocolData {
    InitiatingBundle {
        who: Addr,
        data: InitiatingBundle,
    },
    CryptMessage {
        payload: DoubleRatchetMessage,
        data_type: MessageType,
        sender: Addr,
    },
    Null,
}

pub enum TimeData {
    PrekeyRotation,
}

pub enum DBData {
    IdentityKey(PublicKey),
    Prekey(PrekeyBundle),
    Otk(Option<PublicKey>)
}

pub enum DbWrite {
    Prekey(PrekeyBundle),
}

pub trait CryptoProtocol {
    fn new_conversation(
        &mut self,
        target: &Addr,
        peer_identity_key: PublicKey,
        prekey: &PrekeyBundle,
        otk: &Option<PublicKey>,
    ) -> Result<InitiatingBundle, ProtocolError>;

    fn resolve_conversation_request(
        &mut self,
        from: &Addr,
        handshake_data: &InitiatingBundle,
    ) -> Result<(), ProtocolError>;

    fn send_message(&mut self, target: &Addr, message: DecodedMessage) -> Result<CryptMessage, ProtocolError>;
    
    fn decrypt_message(
        &mut self,
        ciphertext: CryptMessage,
    ) -> Result<DecodedMessage, ProtocolError>;

    fn check_keys(&self) -> usize;
    fn conversation_exists(&self, target: &Addr) -> bool;
    fn generate_keys(&mut self, count: usize) -> Vec<PrekeyBundle>;
}

pub trait DbQueryBuilder {
    fn add(self: Box<Self>, query: DbQuery) -> Box<dyn DbQueryBuilder>;
    fn execute(self: Box<Self>) -> RequestID;
}

pub trait DataServer {
    fn send_else_cache_data(&self, data: ProtocolData);
}

pub trait DbAccessProtocol {
    fn query_db(&self, query: DbQuery) -> Box<dyn DbQueryBuilder>;
    fn write_db_or_cache(&self, data: DbWrite);
}

pub trait UserInterface {
    fn new_message(&mut self, message: DecodedMessage);
    fn protocol_error(&mut self, err: &ProtocolError);
}


impl ProtocolData {
    pub fn crypt_msg_as_decoded(&self,
        receiver: &mut Box<dyn DoubleRatchetProtocolImplementor>,
    ) -> Result<DecodedMessage, ProtocolError>
    {
        let ProtocolData::CryptMessage { payload, data_type, sender } = self else {
            return Err(ProtocolError::LogicFault { reason: "Attempted to convert non-crypt message into decoded message.".into() })
        };
        let raw_data = receiver.recv(payload)?;
        Ok(DecodedMessage {
            payload: raw_data,
            datatype: data_type.clone(),
            sender: sender.clone(),
        })
    }

    pub fn self_as_crypt_msg(self) -> Result<CryptMessage, ProtocolError> {
        match self {
            ProtocolData::CryptMessage { payload, data_type, sender } => Ok(CryptMessage { payload, datatype: data_type, sender }),
            _ => Err(ProtocolError::LogicFault { reason: "Attempted to coerce non-encrypted data into encrypted data.".into() }),
        }
    }
}

impl CryptMessage {
    pub fn self_as_protocol_data(self) -> ProtocolData {
        ProtocolData::CryptMessage {
            payload: self.payload,
            data_type: self.datatype,
            sender: self.sender,
        }
    }
}