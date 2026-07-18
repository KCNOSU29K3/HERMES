use error_set::error_set;
use hcrypt::errors;
use rmp_serde::{encode, decode};

use crate::datatypes::{RequestID, Addr};

error_set! {
    pub ProtocolError := {
        ConversationNotFound,
        HandshakeError,
        DecryptionError(errors::DecryptionError),
        DoubleRatchetError(errors::DoubleRatchetError),
        EncodeError(encode::Error),
        DecodeError(decode::Error),
        FailedRequest {
            reason: String
        },
        UnknownRequest {
            request_id: RequestID
        },
        UnknownUser {
            user: Addr,
            reason: String
        },
        LogicFault {
            reason: String
        }
    }
}