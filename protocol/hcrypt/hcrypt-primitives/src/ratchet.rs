use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};


pub const RATCHET_KEY_INIT_LENGTH:usize = 32;
/// An implementation of a KDF chain as specified by
/// Signal's Double Ratchet Protocol.
///
/// The ratchet is implemented using the HKDF algorithm.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Ratchet {
    state: [u8; 32],
    #[serde_as(as = "[_; 64]")]
    hkdf_buff: [u8; 64],
}

impl Ratchet {
    /// Creates a new ratchet given a key.
    ///
    /// # Arguments
    ///
    /// `key` - The 32 byte key to initiate the state with.
    ///
    /// # Returns
    ///
    /// A new `Ratchet`.
    pub fn new(key: [u8; RATCHET_KEY_INIT_LENGTH]) -> Self {
        return Self {
            state: key,
            hkdf_buff: [0u8; 64],
        };
    }

    /// Turn the ratchet, generating a new value.
    ///
    /// # Arguments
    ///
    /// `key_buffer` - The buffer to write the new value into. Must be of length
    /// 32.
    ///
    /// `input` - an optional byte slice value that will be passed to the KDF when
    /// turning the ratchet.
    pub fn next(&mut self, key_buffer: &mut [u8], input: Option<&[u8]>) {
        let hk;

        // append input if there
        if let Some(byte_array) = input {
            hk = Hkdf::<Sha256>::new(None, [&self.state, byte_array].concat().as_slice());
        } else {
            hk = Hkdf::<Sha256>::new(None, &self.state);
        }
        hk.expand(&[], &mut self.hkdf_buff).unwrap();

        // update and return values
        self.state.copy_from_slice(&self.hkdf_buff[0..32]);
        key_buffer.copy_from_slice(&self.hkdf_buff[32..64]);

        // clear our buffered data
        self.hkdf_buff.zeroize();
    }
}

impl Zeroize for Ratchet {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl ZeroizeOnDrop for Ratchet {}
