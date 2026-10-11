//! Integration tests for the protocol.
//! 
//! This integration test will avoid implementation of IO layers, persistent DB storage, and other
//! production variables. This integration test will test only the protocol itself.


#[cfg(test)]
mod protocol_tests {
    use crate::{
        datatypes::{Addr, CryptMessage, DecodedMessage},
        errors::ProtocolError,
        traits::CryptoProtocol,
    };

    use hcrypt::{
        key::{PublicKey, Signature},
        double_ratchet::{InitiatingBundle, PrekeyBundle},
    };

    struct CryptoProtocolImpl {
        
    }

    impl CryptoProtocol for CryptoProtocolImpl {
        fn new_conversation(
            &mut self,
            target: &Addr,
            peer_identity_key: PublicKey,
            prekey: &PrekeyBundle,
            otk: &Option<PublicKey>,
        ) -> Result<InitiatingBundle, ProtocolError> {
            
            todo!()
        }

        fn delete_conversation(&mut self, target: &Addr) -> Result<(), ProtocolError> {
            todo!()
        }

        fn resolve_conversation_request(
            &mut self,
            from: &Addr,
            handshake_data: &InitiatingBundle,
        ) -> Result<(), ProtocolError> {
            todo!()
        }

        fn send_message(&mut self, target: &Addr, message: DecodedMessage) -> Result<CryptMessage, ProtocolError> {
            todo!()
        }

        fn decrypt_message(
            &mut self,
            ciphertext: CryptMessage,
        ) -> Result<DecodedMessage, ProtocolError> {
            todo!()
        }

        fn rotate_prekey(&mut self) -> (PublicKey, Signature) {
            todo!()
        }

        fn check_keys(&self) -> usize {
            todo!()
        }

        fn conversation_exists(&self, target: &Addr) -> bool {
            todo!()
        }

        fn generate_keys(&mut self, count: usize) -> Vec<PrekeyBundle> {
            todo!()
        }
    }
    
    #[test]
    fn generate_new_protocol() {
        
    }
}
