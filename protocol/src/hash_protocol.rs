
use std::hash::{Hasher};

/// Defines the hash protocol used throughout the protocol.
pub trait HashProtocolFactory: Hasher {
    fn new() -> Self;
}