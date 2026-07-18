use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, OsRng},
};

use rand_core::RngCore;

use crate::errors::DecryptionError;

const NONCE_SIZE:usize = 12;

/// Primitive method for encrypting data.
///
/// Encrypts data using AES-256 in GCM mode, with a randomly generated nonce that is
/// prepended to the ciphertext and zeroized after use. This does NOT zeroize the provided
/// key nor the payload, and as such care should be taken to ensure that they are effectively
/// zeroized after encryption.
///
/// Returns a u8 vector containing the ciphertext.
/// 
/// This function will panic if `aes-gcm` would panic with provided inputs.
pub fn encrypt(key: &[u8], payload: &[u8]) -> Vec<u8> {

    let cipher = Aes256Gcm::new(key.into());

    let mut nonce = [0u8; NONCE_SIZE].to_vec();
    OsRng.fill_bytes(&mut nonce);
    
    let ciphertext = match cipher.encrypt(nonce[0..NONCE_SIZE].into(), payload) {
        Ok(val) => val,
        // this is a genuine error, and pretty irrecoverable.
        Err(err) => panic!("Encryption failed: {}", err),
    };

    [
        nonce,
        ciphertext,
    ].concat()    
}

/// primitive method for decrypting data.
///
/// decrypts data using AES-256 in GCM mode. Ciphertext must have been generated using
/// the primitive encryption function, as the ciphertext will contain nonce and authentication
/// data. Does NOT zeroize the key, so care must be taken to zeroize the key after use.
///
/// Returns a u8 vector containing the plaintext data.
///
/// This function will not Panic.
pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    if ciphertext.len() < NONCE_SIZE {
        return Err(DecryptionError::InvalidCipherText {
            reason: "Ciphertext shorter than nonce length.".into(),
        });
    }

    let cipher = Aes256Gcm::new(key.into());

    let nonce = &ciphertext[0..NONCE_SIZE];
    let ciphertext = &ciphertext[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| DecryptionError::InvalidKey)?;

    Ok(plaintext)
}


