use hcrypt::{double_ratchet::{InitiatingBundle, PrekeyBundle}, key::{PublicKey, Signature}};

use crate::{datatypes::{Addr, CryptMessage, DecodedMessage, ProtocolData, RequestID}, errors::ProtocolError, networking::{DbQuery, DbWrite}};




pub trait DbQueryBuilder {
    fn add(&mut self, query: DbQuery) -> &mut dyn DbQueryBuilder;
    fn execute(&mut self) -> RequestID;
}

pub trait DbWriteBuilder {
    fn add(&mut self, data: DbWrite) -> &mut dyn DbWriteBuilder;
    fn write_or_cache(&mut self);
}



pub trait DbAccessProtocol {
    fn query_db(&self) -> Box<dyn DbQueryBuilder>;
    fn write_db(&self) -> Box<dyn DbWriteBuilder>;
}

pub trait DataServer {
    fn send_else_cache_data(&self, data: ProtocolData);
}

pub trait CryptoProtocol {
    fn new_conversation(
        &mut self,
        target: &Addr,
        peer_identity_key: PublicKey,
        prekey: &PrekeyBundle,
        otk: &Option<PublicKey>,
    ) -> Result<InitiatingBundle, ProtocolError>;

    fn delete_conversation(&mut self, target: &Addr) -> Result<(), ProtocolError>;

    fn resolve_conversation_request(
        &mut self,
        from: &Addr,
        handshake_data: &InitiatingBundle,
    ) -> Result<(), ProtocolError>;

    fn send_message(&mut self, target: &Addr, message: DecodedMessage) -> Result<CryptMessage, ProtocolError>;
    
    fn decrypt_message(
        &mut self,
        ciphertext: CryptMessage,
    ) -> Result<DecodedMessage, ProtocolError>;

    fn rotate_prekey(&mut self) -> (PublicKey, Signature);

    fn check_keys(&self) -> usize;
    fn conversation_exists(&self, target: &Addr) -> bool;
    fn generate_keys(&mut self, count: usize) -> Vec<PrekeyBundle>;
}

pub trait UserInterface {
    fn new_message(&mut self, message: DecodedMessage);
    fn protocol_error(&mut self, err: &ProtocolError);
}