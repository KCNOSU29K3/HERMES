
use error_set::error_set;
use hcrypt::errors;
use rmp_serde::{decode, encode};

use crate::datatypes::{Addr, RequestID};

error_set! {
    #[allow(clippy::all)]
    pub ProtocolError := {
        ConversationNotFound,
        HandshakeError,
        DecryptionError(errors::DecryptionError),
        DoubleRatchetError(errors::DoubleRatchetError),
        EncodeError(encode::Error),
        DecodeError(decode::Error),
        #[display("Request failed: {reason}.")]
        FailedRequest {
            reason: String
        },
        #[display("attempted to resolve non-existent request: {request_id}.")]
        UnknownRequest {
            request_id: RequestID
        },
        #[display("received request from user: {user} that could not be resolved because: {reason}.")]
        UnknownUser {
            user: Addr,
            reason: String
        },
        #[display("protocol logic fault: {reason}.")]
        LogicFault {
            reason: String
        }
    }
}
