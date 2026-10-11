use error_set::error_set;
use serde::{Deserialize, Serialize};



error_set! {
    pub SymmetricKeyGenerationError := {
        #[display("Argon2 failed to generate key: {reason}")]
        Argon2GenerationError {
            reason:String
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub DecryptionError := {
        InvalidKey,
        #[display("Fault when decrypting: {reason}")]
        InvalidCipherText {
            reason:String
        },
        InvalidSignature
    } || SymmetricKeyGenerationError

    #[derive(Serialize, Deserialize, Clone)]
    pub DoubleRatchetError := {
        OutOfQueueSpace,
        NonExistentKey
    } || DecryptionError
}
