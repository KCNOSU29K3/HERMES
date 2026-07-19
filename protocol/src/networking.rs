
// use std::collections::HashMap;

// use uuid::Uuid;

// pub type NetworkID = Uuid;
// pub struct Networker {
//     pending_dispatches: HashMap<NetworkID, Vec<u8>>}


// impl Networker {
//     pub fn new() -> Self {
//         Self {
//             pending_dispatches: HashMap::new(),
//         }
//     }

//     pub fn queue(&mut self, network_id: NetworkID, data: Vec<u8>) {
//         self.pending_dispatches.insert(network_id, data);
//     }

//     pub fn resolve(&mut self, network_id: NetworkID) -> Option<Vec<u8>> {
//         self.pending_dispatches.remove(&network_id)
//     }

//     pub fn obtain(&mut self, network_id: NetworkID) -> Option<&Vec<u8>> {
//         self.pending_dispatches.get(&network_id)
//     }
// }
// 

use hcrypt::{double_ratchet::PrekeyBundle, key::PublicKey};

use crate::errors::ProtocolError;
#[derive(Debug)]
pub enum DbQuery {
    IdentityKey,
    Prekey,
    Otk,
}

pub enum DBData {
    IdentityKey(PublicKey),
    Prekey(PrekeyBundle),
    Otk(Option<PublicKey>)
}

pub enum DbWrite {
    Prekey(PrekeyBundle),
}

impl TryFrom<DBData> for PublicKey {
    type Error = ProtocolError;

    fn try_from(value: DBData) -> Result<Self, Self::Error> {
        match value {
            DBData::IdentityKey(key) => Ok(key),
            DBData::Prekey(_) => Err(ProtocolError::FailedRequest { reason: "Expected identity key but got prekey".into() }),
            DBData::Otk(_) => Err(ProtocolError::FailedRequest { reason: "Expected identity key but got otk".into() }),
        }
    }
}

impl TryFrom<DBData> for PrekeyBundle {
    type Error = ProtocolError;

    fn try_from(value: DBData) -> Result<Self, Self::Error> {
        match value {
            DBData::Prekey(bundle) => Ok(bundle),
            DBData::IdentityKey(_) => Err(ProtocolError::FailedRequest { reason: "Expected prekey but got identity key".into() }),
            DBData::Otk(_) => Err(ProtocolError::FailedRequest { reason: "Expected prekey but got otk".into() }),
        }
    }
}

impl TryFrom<DBData> for Option<PublicKey> {
    type Error = ProtocolError;

    fn try_from(value: DBData) -> Result<Self, Self::Error> {
        match value {
            DBData::Otk(otk) => Ok(otk),
            DBData::IdentityKey(_) => Err(ProtocolError::FailedRequest { reason: "Expected otk but got identity key".into() }),
            DBData::Prekey(_) => Err(ProtocolError::FailedRequest { reason: "Expected otk but got prekey".into() }),
        }
    }
}
