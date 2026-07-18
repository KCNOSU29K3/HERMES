use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use hcrypt_primitives::x25519::{RawPrivateKey};
pub use hcrypt_primitives::x25519::{PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH, AGREEMENT_LENGTH, SIGNATURE_LENGTH};

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Clone)]
/// An implementation of a XEd25519 key.
///
/// The XEd25519 implementation allows for the support of signing, verifying, and ECDH.
pub struct PrivateKey {
    private_key: RawPrivateKey,
}

impl Eq for PrivateKey {}

pub type Signature = [u8; SIGNATURE_LENGTH];
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];
pub type ExportedPrivateKey = [u8; PRIVATE_KEY_LENGTH];
pub type KeyExchangeSecret = [u8; AGREEMENT_LENGTH];

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateKey {
    /// creates a new key from a given scalar.
    ///
    /// consumes the scalar.
    pub fn load(key: [u8; PRIVATE_KEY_LENGTH]) -> Self {
        Self {
            private_key: RawPrivateKey::from(key),
        }
    }

    /// Generates a new private key.
    pub fn new() -> Self {
        Self {
            private_key: RawPrivateKey::new(&mut OsRng),
        }
    }

    /// Returns the public counterpart to this key.
    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    /// Performs a ECDH exchange with a given peer key.
    ///
    /// # Arguments
    ///
    /// `peer_key` - The public key of the other party. Must be 32 bytes long.
    pub fn exchange(&self, peer_key: &PublicKey) -> KeyExchangeSecret {
        self.private_key.exchange(peer_key)
    }

    /// Signs data with this key for verification purposes.
    ///
    /// # Arguments
    ///
    /// `data` - The data to sign.
    ///
    /// # Returns
    ///
    /// The generated signature, as a [u8] slice of length 64.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.private_key.sign(&mut OsRng, &[data])
    }

    /// Verifies from a peer given their public key.
    ///
    /// # Arguments
    ///
    /// `peer_key` - The key to verify with, as a [u8] slice of length 32.
    ///
    /// `data` - the data to be verify as a [u8] slice.
    ///
    /// `signature` - The signature to verify, as a [u8] slice of length 64.
    pub fn verify(peer_key: &PublicKey, data: &[u8], signature: &Signature) -> bool {
        RawPrivateKey::verify(peer_key, &[data], signature)
    }

    /// Returns the private scalar value as a vector of length 32.
    pub fn private_key(&self) -> ExportedPrivateKey {
        self.private_key.private_key()
    }
}

impl From<RawPrivateKey> for PrivateKey {
    fn from(value: RawPrivateKey) -> Self {
        Self {
            private_key: value,
        }
    }
}
