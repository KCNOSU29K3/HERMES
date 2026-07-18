//! Provides implementations for ECIES encryption and decryption.
//!
//! Exports the following functions:
//! * `ecies_encrypt`
//! * `ecies_decrypt`

use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use hcrypt_primitives::{
    aes::{encrypt, decrypt},
    errors::{DecryptionError, SymmetricKeyGenerationError},
    kdf::argon2,
};

use crate::key::{PrivateKey, PublicKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

const SALT_LENGTH: usize = 16;
const MINIMUM_ECIES_ENCRYPT_LENGTH: usize = PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH + SALT_LENGTH;

/// Encrypts byte data through an ECIES protocol.
///
/// Uses a 32 byte public key as the encryption key, and a provided private key as
/// the signing key.
///
/// If the internal key generation done after the Elliptic Curve Diffie Hellman Exchange
/// fails, this function will return an error. Otherwise, returns a [u8] [Vec].
///
/// # Examples
/// ```rust
/// use cryptography_package::core::primitives::{generate_key_pair, ecies_encrypt, ecies_decrypt};
///
/// let alice_private_key = generate_key_pair();
/// let bob_private_key = generate_key_pair();
///
/// let alice_message = b"Hello, World!";
/// let bob_message = b"Hello, World!";
///
/// let message_for_bob = ecies_encrypt(
///     &bob_private_key.public_key(),
///     &alice_private_key,
///     alice_message,
/// ).unwrap();
/// let message_for_alice = ecies_encrypt(
///     &alice_private_key.public_key(),
///     &bob_private_key,
///     bob_message,
/// ).unwrap();
///
/// let bob_decoded_message = ecies_decrypt(
///     &bob_private_key,
///     &alice_private_key.public_key(),
///     &message_for_bob,
/// ).unwrap();
/// let alice_decoded_message = ecies_decrypt(
///     &alice_private_key,
///     &bob_private_key.public_key(),
///     &message_for_alice,
/// ).unwrap();
///
/// assert!(bob_decoded_message == alice_decoded_message)
/// ```
pub fn ecies_encrypt(
    encryption_key: &PublicKey,
    signing_key: &PrivateKey,
    data: &[u8],
) -> Result<Vec<u8>, SymmetricKeyGenerationError> {

    let data_encryption_key = PrivateKey::new();
    let mut secret = data_encryption_key.exchange(encryption_key);

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let encryption_key = argon2(&secret, &salt)?;
    secret.zeroize();

    let encrypted_data = encrypt(&encryption_key, data);
    let signature = signing_key.sign(&encrypted_data);

    let payload = [
        data_encryption_key.public_key().as_slice(),
        signature.as_slice(),
        salt.as_slice(),
        encrypted_data.as_slice(),
    ].concat();

    Ok(payload)
}

/// Decrypts a generated ciphertext through an ECIES protocol.
///
/// Uses a provided private key for decryption; this must be the private analogue to the
/// public key used for encryption. Additionally uses a provided public key for verification;
/// this must be the public analogue to the private key used for signing.
///
/// If an error in decryption occurs - IE an incorrect shared key is calculated from incorrect
/// parameters, the decrypted data fails the verification stage, etc - this function will return an
/// Error.
///
/// # Examples
/// ```rust
/// use cryptography_package::core::primitives::{generate_key_pair, ecies_encrypt, ecies_decrypt};
///
/// let alice_private_key = generate_key_pair();
/// let bob_private_key = generate_key_pair();
///
/// let alice_message = b"Hello, World!";
/// let bob_message = b"Hello, World!";
///
/// let message_for_bob = ecies_encrypt(
///     &bob_private_key.public_key(),
///     &alice_private_key,
///     alice_message,
/// ).unwrap();
/// let message_for_alice = ecies_encrypt(
///     &alice_private_key.public_key(),
///     &bob_private_key,
///     bob_message,
/// ).unwrap();
///
/// let bob_decoded_message = ecies_decrypt(
///     &bob_private_key,
///     &alice_private_key.public_key(),
///     &message_for_bob,
/// ).unwrap();
/// let alice_decoded_message = ecies_decrypt(
///     &alice_private_key,
///     &bob_private_key.public_key(),
///     &message_for_alice,
/// ).unwrap();
///
/// assert!(bob_decoded_message == alice_decoded_message)
/// ```
pub fn ecies_decrypt(
    decryption_key: &PrivateKey,
    verification_key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ciphertext.len() < MINIMUM_ECIES_ENCRYPT_LENGTH {
        return Err(DecryptionError::InvalidCipherText {
            reason: "Provided ciphertext is shorter than minimum ciphertext length.".into(),
        });
    }

    let public_encryption_key_buffer: [u8; PUBLIC_KEY_LENGTH] = ciphertext[0..PUBLIC_KEY_LENGTH].try_into().unwrap();
    let signature_buffer: [u8; SIGNATURE_LENGTH] = ciphertext[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH+SIGNATURE_LENGTH].try_into().unwrap();
    let salt_buffer: [u8; SALT_LENGTH] = ciphertext[SIGNATURE_LENGTH+PUBLIC_KEY_LENGTH..MINIMUM_ECIES_ENCRYPT_LENGTH].try_into().unwrap();
    let payload = &ciphertext[MINIMUM_ECIES_ENCRYPT_LENGTH..];

    if !PrivateKey::verify(verification_key, payload, &signature_buffer) {
        return Err(DecryptionError::InvalidSignature);
    }

    let mut dh_secret = decryption_key.exchange(&public_encryption_key_buffer);
    let decryption_key = argon2(&dh_secret, &salt_buffer)?;
    dh_secret.zeroize();

    let decrypted_data = decrypt(&decryption_key, payload)?;

    Ok(decrypted_data)
}
