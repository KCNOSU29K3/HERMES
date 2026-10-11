use hcrypt::{double_ratchet::{InitiatingBundle, PrekeyBundle}, key::{PublicKey, Signature}};

use crate::{datatypes::{Addr, CryptMessage, DecodedMessage, ProtocolData, RequestID}, errors::ProtocolError, networking::{DbQuery, DbWrite}};



/// Builder trait for constructing complex DB query operations.
/// 
/// Upon evaluation, the Implementor must execute the query operations in order, and return the 
/// resultant data in order.
pub trait DbQueryBuilder {
    /// Adds a DB query operation to the overall query.
    /// This function must return a mutable reference to a builder with
    /// the query and all previous queries added to itself.
    fn add(&mut self, query: DbQuery) -> &mut dyn DbQueryBuilder;

    /// Executes the query operation. Upon evaluation, the Implementor must
    /// provide a unique request ID that corresponds to this query.
    /// 
    /// The Implementor is responsible for handling request timeouts. In the event of a request timeout,
    /// the Implementor must provide the Protocol with the unique request ID so it can be cancelled.
    /// 
    /// If the query succeeds, data must be returned in the order it was requested.
    fn execute(&mut self) -> RequestID;
}


/// Builder trait for constructing complex DB write operations.
/// 
/// Upon evaluation, the Implementor may execute the write operations in any order.
/// The implementor does not need to provide a unique request ID for each write operation.
pub trait DbWriteBuilder {
    /// Adds a DB write operation the the overall write.
    /// This function must return a mutable reference to a builder with
    /// the write and all previous writes added to itself.
    fn add(&mut self, data: DbWrite) -> &mut dyn DbWriteBuilder;

    /// Executes the write operation. If the write operation cannot be completed at call time,
    /// the IO implementor must cache the operation and retry it later. The IO implementor cannot
    /// discard the call until the write executes successfully. Doing so will result in all data
    /// included in the DB write being lost.
    fn write_or_cache(&mut self);
}



pub trait DbAccessProtocol {
    /// Returns a query builder for the database. This function will return a builder that can only 
    /// execute read operations on the database.
    fn query_db(&self) -> Box<dyn DbQueryBuilder>;

    /// Returns a write builder for the database. This function will return a builder that can only
    /// execute write operations on the database.
    fn write_db(&self) -> Box<dyn DbWriteBuilder>;
}

/// Abstraction for interactions with dispatching data to another user.
/// The Implementor of this trait is responsible for routing the data to the correct recipient.
pub trait DataServer {
    /// Sends the data to the recipient, or caches it if the IO layer was unable to connect.
    /// The Implementor MUST cache provided data until the connection is reestablished, as the Protocol
    /// makes the assumption that all data sent is eventually delivered.
    fn send_else_cache_data(&self, who:&Addr, data: ProtocolData);
}


/// Abstractions for interactions with the Cryptographic Protocol.
/// 
/// The Implementor of this trait is responsible for managing extant conversations, creating new conversations, maintaining 
/// OTK levels per Signals Double Ratchet Protocol, 
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