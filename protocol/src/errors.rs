
use std::fmt::Display;
use std::error::Error;

use error_set::error_set;
use hcrypt::errors;
use rmp_serde::{decode, encode};

use crate::datatypes::{Addr, RequestID};

#[derive(Clone, Debug)]
pub struct ConversionError {
    pub error: String,
}

impl From<decode::Error> for ConversionError {
    fn from(error: decode::Error) -> Self {
        Self {
            error: error.to_string(),
        }
    }
}

impl From<encode::Error> for ConversionError {
    fn from(error: encode::Error) -> Self {
        Self {
            error: error.to_string(),
        }
    }
}

impl Error for ConversionError {}

impl Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}



error_set! {
    #[allow(clippy::all)]
    #[derive(Clone)]
    pub ProtocolError := {
        ConversationNotFound,
        HandshakeError,
        DecryptionError(errors::DecryptionError),
        DoubleRatchetError(errors::DoubleRatchetError),
        EncodeError(ConversionError),
        DecodeError(ConversionError),
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
