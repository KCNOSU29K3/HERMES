use crate::errors::SymmetricKeyGenerationError;
use argon2::Argon2;

pub const GENERATED_KEY_SIZE: usize = 32;

// we accept the salt param so we don't have to export
// both of these, and create a new struct for them and whatnot
// we can just take an input from node.crypto.randomBytes()

/// Generates a 256 bit key for encryption.
///
/// uses Argon2 to create a cryptographically strong encryption key.
///
/// # Arguments
///
/// `input` - The input or "password" to base the key on.
///
/// `salt` - random data to salt the password with.
///
/// # Returns
///
/// A u8 vector containing the generated key.
///
/// # Panics
///
/// This function will panic if the key could not be generated.
pub fn argon2(
    input: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, SymmetricKeyGenerationError> {
    let mut tmp = [0u8; GENERATED_KEY_SIZE];
    Argon2::default()
        .hash_password_into(input, salt, &mut tmp)
        .map_err(|e| SymmetricKeyGenerationError::Argon2GenerationError {
            reason: e.to_string(),
        })?;

    Ok(tmp.into())
}

#[test]
fn test_key_generation() {
    let password = b"test";
    let salt = b"Lorem Ipsum Dolo";
    let raw_key_values = [
        22, 77, 166, 57, 104, 174, 110, 186, 69, 146, 189, 166, 103, 47, 180, 54, 137, 51, 246, 94,
        76, 138, 18, 61, 171, 230, 190, 105, 184, 197, 168, 132,
    ];
    let _key = argon2(password, salt).unwrap();
    assert!(_key == raw_key_values)
}
