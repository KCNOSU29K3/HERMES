use hkdf::Hkdf;
use sha2::{Sha256, Sha512};


pub enum HashProtocol {
    Sha256(Hkdf<Sha256>),
    Sha512(Hkdf<Sha512>)
}

pub struct HKDF {
    protocol:HashProtocol
}

impl HashProtocol {
    pub fn sha256(salt:Option<&[u8]>, ikm: &[u8]) -> Self {let kdf = Hkdf::<Sha256>::new(salt, ikm); return HashProtocol::Sha256(kdf) }
    pub fn sha512(salt:Option<&[u8]>, ikm: &[u8]) -> Self {let kdf = Hkdf::<Sha512>::new(salt, ikm); return HashProtocol::Sha512(kdf) }
    pub fn to_hkdf(self) -> HKDF {return HKDF {protocol: self} }


    fn expand(&self, info:Option<&[u8]>, len:usize) -> Vec<u8> {
        let mut result = vec![0u8; len];
        let determined_info;
        if let Some(info) = info {
            determined_info = info;
        } else {
            determined_info = &[];
        }

        match self {
            Self::Sha256(kdf) => {
                kdf.expand(determined_info, &mut result).expect("SHA 256 HASHER FAILED");
            }
            Self::Sha512(kdf) => {
                kdf.expand(determined_info, &mut result).expect("SHA 256 HASHER FAILED");
            }
        };
        result
    }
}

impl HKDF {
    pub fn expand(&self, info: Option<&[u8]>, len: usize) -> Vec<u8> {
        self.protocol.expand(info, len)
    }
}