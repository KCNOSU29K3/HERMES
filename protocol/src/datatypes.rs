use hcrypt::double_ratchet::{DoubleRatchetMessage, DoubleRatchetProtocolImplementor, InitiatingBundle};
use serde::{Deserialize, Serialize};

use crate::{errors::ProtocolError};
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