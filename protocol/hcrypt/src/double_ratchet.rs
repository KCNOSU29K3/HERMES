use serde::{Deserialize, Serialize};
use std::{
    hash::Hash,
    collections::HashMap,
    hash::Hasher,
};

use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::key::{PrivateKey, PublicKey, Signature};

use hcrypt_derive::New;
use hcrypt_primitives::{
    aes::{decrypt, encrypt},
    errors::{DecryptionError, DoubleRatchetError},
    hkdf::HashProtocol,
    ratchet::{RATCHET_KEY_INIT_LENGTH, Ratchet},
};

pub const MAX_MESSAGE_QUEUE: u16 = 1000;
pub const SECRET_KEY_LENGTH: usize = 32;
const PROTOCOL_INFO: &[u8] = "HERMES PROTOCOL 1.0.0".as_bytes();

type DecryptionKey = [u8; 32];

macro_rules! advance_ratchet {
    ($ratchet:expr, $key_buff:expr, $input:expr) => {
        $ratchet.next(&mut $key_buff, ($input))
    };
}

macro_rules! switch_ratchet {
    ($self:ident, $target:ident, $dh_shared:ident) => {
        advance_ratchet!($self.root_ratchet, $self.key_buff, Some(&$dh_shared));
        $self.$target = Ratchet::new($self.key_buff);
        $self.zero_buffers();
    };
}

fn initialize_ratchets(initiator: bool, root: &mut Ratchet) -> (Ratchet, Ratchet) {
    let mut key_buff = [0u8; 32];
    root.next(&mut key_buff, None);
    let first_ratchet = Ratchet::new(key_buff);
    key_buff.zeroize();

    root.next(&mut key_buff, None);
    let second_ratchet = Ratchet::new(key_buff);
    key_buff.zeroize();

    if initiator {
        (first_ratchet, second_ratchet)
    } else {
        (second_ratchet, first_ratchet)
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Debug, PartialEq, New)]
pub struct DoubleRatchetMessage {
    pub ciphertext: Vec<u8>,
    pub public_key: PublicKey,
    pub previous_chain_count: u16,
    pub current_chain_count: u16,
}

#[derive(Hash, PartialEq, Eq, New, Clone)]
pub struct PrivateKeyBundle {
    pub prekey: PrivateKey,
    pub one_time_key: PrivateKey,
}

#[derive(New, Serialize, Deserialize)]
pub struct InitiatingBundle {
    pub otk_hash: Option<u64>,
    pub identity_key: PublicKey,
    pub ephemeral_key: PublicKey,
}

// #[derive(Eq, Debug)]
// pub struct PublicKeyBundle {
//     pub prekey: PublicKey,
//     pub prekey_signature: Signature,
//     pub one_time_key: PublicKey,
// }
//
#[derive(Clone)]
pub struct PrekeyBundle {
    pub prekey: PublicKey,
    pub prekey_signature: Signature,
}

/// Shared algorithms used to execute the Double Ratchet protocol.
#[derive(Serialize, Deserialize)]
pub struct Fundamentals {
    /// The Identity key of this end of the protocol.
    /// Used to provide identity authentication in the
    /// protocol.
    identity_pair: PrivateKey,

    /// The ratchet used to seed the send/receive ratchets.
    /// Initialized from a shared secret derives through X3DH.
    root_ratchet: Ratchet,

    /// The ratchet used to generate decryption key values.
    receiving_ratchet: Ratchet,

    /// The ratchet used to generate encryption key values.
    sending_ratchet: Ratchet,

    /// The current peer ratchet public key. This value is
    /// optional as it will be automatically set upon receiving
    /// the first message.
    peer_ratchet_key: Option<PublicKey>,

    /// The Private key used to execute ECDH handshakes with the
    /// peer's public ratchet key, maintaining forward secrecy.
    dh_ratchet_pair: PrivateKey,

    /// A Hashmap for housing decryption keys for lost messages.
    /// The hashmap key is comprised of the public ratchet key
    /// the provided message was encrypted with, the message number
    /// for this public key, and the decryption key for the message
    /// that corresponds to these values.
    skipped_message_keys: HashMap<(PublicKey, [u8; 2]), DecryptionKey>,

    /// The number of messages sent before resetting the ratchets
    /// using the shared secret derived through ECDH with the DH
    /// ratchet pair.
    number_sent: u16,

    /// The number of messages received before resetting the ratchets
    /// using the shared secret derived through ECDH with the DH
    /// ratchet pair.
    number_received: u16,

    /// The total amount of messages sent using the last ratchet set.
    /// Appended to messages to allow for the peer to skip lost messages
    /// and store their keys for later.
    prev_send_chain_num: u16,

    /// An owned buffer used to house ratchet keys.
    key_buff: DecryptionKey,

    /// State lock that prevents exporting of state more than once.
    is_initiator: bool,
}

/// An implementation of the Double Ratchet protocol designed to
/// accept double ratchet conversations.
#[derive(Serialize, Deserialize)]
pub struct Initiator {
    core: Fundamentals,
}

/// An implementation of the Double Ratchet protocol designed to
/// request double ratchet conversations.
#[derive(Serialize, Deserialize)]
pub struct Responder {
    core: Fundamentals,
}

impl Fundamentals {
    /// Initializes the core implementation.
    ///
    /// # Arguments
    /// `key` - The shared key to initiate the root ratchet with. Should be derived through
    /// X3DH.
    ///
    /// `identity_key` - The identity key of the user, used to execute DH ratchet steps.
    ///
    /// `is_initiator` - boolean flag that changes the order the sending and receiving ratchets
    /// are instantiated.
    pub fn initialize(
        key: [u8; RATCHET_KEY_INIT_LENGTH],
        identity_key: PrivateKey,
        is_initiator: bool,
    ) -> Self {
        let mut root_ratchet = Ratchet::new(key);

        let (sending_ratchet, receiving_ratchet) =
            initialize_ratchets(is_initiator, &mut root_ratchet);

        Self {
            identity_pair: identity_key,
            root_ratchet,
            receiving_ratchet,
            sending_ratchet,
            peer_ratchet_key: None,
            dh_ratchet_pair: PrivateKey::new(),
            skipped_message_keys: HashMap::new(),
            number_sent: 0,
            number_received: 0,
            prev_send_chain_num: 0,
            key_buff: [0u8; 32],
            is_initiator,
        }
    }

    /// Executes a DH ratchet step.
    fn dh_ratchet(&mut self, message_public_key: PublicKey) {
        // change the receiving ratchet.
        // unlike the initialization, this does not have to be done in a specific
        // order, since the ratchets are already sync'd.
        let dh_shared = self.dh_ratchet_pair.exchange(&message_public_key);
        switch_ratchet!(self, sending_ratchet, dh_shared);

        self.dh_ratchet_pair = PrivateKey::new();
        let dh_shared = self.dh_ratchet_pair.exchange(&message_public_key);
        switch_ratchet!(self, receiving_ratchet, dh_shared);

        self.peer_ratchet_key = Some(message_public_key);
        self.prev_send_chain_num = self.number_sent;
        self.number_sent = 0;
        self.number_received = 0;
    }

    /// Serializes and returns a [`DoubleRatchetMessage`].
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage {
        advance_ratchet!(self.sending_ratchet, self.key_buff, None);

        let ciphertext = encrypt(&self.key_buff, message);
        self.zero_buffers();

        let ratchet_msg = DoubleRatchetMessage::new(
            ciphertext,
            self.dh_ratchet_pair.public_key(),
            self.prev_send_chain_num,
            self.number_sent,
        );

        self.number_sent += 1;
        ratchet_msg
    }

    /// Generates the decryption key for a given [`DoubleRatchetMessage`], potentially
    /// skipping keys for missed messages, and returns the the decrypted data.
    ///
    /// # Arguments
    ///
    /// `message` - the message to decrypt.
    ///
    /// # Errors
    ///
    /// This function will return a crate Error if the underlying decryption implementation
    /// fails to decrypt.
    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError> {
        let plaintext = self.attempt_decrypt_with_stored_keys(message)?;
        if let Some(plaintext) = plaintext {
            return Ok(plaintext);
        }

        if self.peer_ratchet_key.is_none() {
            self.peer_ratchet_key = Some(message.public_key)
        }

        // unwrapping is safe since above clause will set the key.
        if self.peer_ratchet_key.unwrap() != message.public_key {
            self.skip_message_keys(&message.previous_chain_count)?;
            self.dh_ratchet(message.public_key);
        }

        self.skip_message_keys(&message.current_chain_count)?;

        // turn once more since skip message keys only skips to every message before this one.
        advance_ratchet!(self.receiving_ratchet, self.key_buff, None);

        self.number_received += 1;
        let plaintext = decrypt(&self.key_buff, &message.ciphertext)?;

        self.zero_buffers();
        Ok(plaintext)
    }

    /// Checks if a given message has an already present decryption key.
    fn attempt_decrypt_with_stored_keys(
        &mut self,
        message: &DoubleRatchetMessage,
    ) -> Result<Option<Vec<u8>>, DecryptionError> {
        let index_key = (
            message.public_key,
            message.current_chain_count.to_be_bytes(),
        );
        if let Some(result) = self.skipped_message_keys.get(&index_key) {
            let plaintext = decrypt(result, &message.ciphertext)?;
            self.skipped_message_keys.remove(&index_key);
            return Ok(Some(plaintext));
        }
        Ok(None)
    }

    /// Skips a given amount of message keys.
    ///
    /// Will return an Error if the amount of keys exceeds the max message
    /// queue.
    fn skip_message_keys(&mut self, until: &u16) -> Result<(), DoubleRatchetError> {
        if self.number_received + MAX_MESSAGE_QUEUE < *until {
            return Err(DoubleRatchetError::OutOfQueueSpace);
        }

        while self.number_received < *until {
            advance_ratchet!(self.receiving_ratchet, self.key_buff, None);

            // its always safe to unwrap here, since the first message will never trigger
            // this while loop and while also set the peer public key.
            // we use both the ratchet public key and the number in the sending chain
            // so we can support all out of order messages in a given chain.
            self.skipped_message_keys.insert(
                (
                    self.peer_ratchet_key.unwrap(),
                    self.number_received.to_be_bytes(),
                ),
                self.key_buff,
            );
            self.zero_buffers();
            self.number_received += 1
        }
        Ok(())
    }

    fn zero_buffers(&mut self) {
        self.key_buff.zeroize();
    }
}

/// An implementation of a Double Ratchet protocol actor.
///
/// An implementation of the initiator of the protocol.
impl Initiator {
    // we do key verification here to ensure that a MITM didn't give us a false set.
    /// Creates a new Initiator actor.
    ///
    /// Required arguments are those as specified in Signals X3DH protocol
    /// using one time keys for the initiator in the protocol, Alice.
    ///
    /// This method may return a Crate Error if the prekey public key signature is
    /// invalid.
    pub fn new(
        identity_key: PrivateKey,
        peer_identity_key: PublicKey,
        peer_prekey: PrekeyBundle,
        otk: Option<PublicKey>,
        hasher: &mut impl Hasher,
    ) -> Result<(Self, InitiatingBundle), DecryptionError> {
        if !PrivateKey::verify(&peer_identity_key, &peer_prekey.prekey, &peer_prekey.prekey_signature) {
            return Err(DecryptionError::InvalidSignature);
        }

        // derive the ephemeral key
        // create bundle hash for receiver
        let ephemeral_key = PrivateKey::new();
        let bundle_hash;
        if let Some(otk) = otk {
            otk.hash(hasher);
            bundle_hash = Some(hasher.finish());
        } else {
            bundle_hash = None;
        }
        let init_bundle = InitiatingBundle::new(
            bundle_hash,
            identity_key.public_key(),
            ephemeral_key.public_key(),
        );

        // compute X3DH
        let mut secret_materials = [
            identity_key.exchange(&peer_prekey.prekey),
            ephemeral_key.exchange(&peer_identity_key),
            ephemeral_key.exchange(&peer_prekey.prekey),
            if let Some (otk) = otk {ephemeral_key.exchange(&otk)} else {[0u8;32]},
        ]
        .concat();

        let mut secret = HashProtocol::sha256(None, &secret_materials)
            .to_hkdf()
            .expand(Some(PROTOCOL_INFO), 32)
            .try_into()
            .expect("SECRET LONGER THAN REQUESTED.");
        secret_materials.zeroize();

        let core = Fundamentals::initialize(secret, identity_key, true);
        secret.zeroize();

        Ok((Self { core }, init_bundle))
    }
}

impl Responder {
    // we DON'T do any key checking here since we are responding. The client will first verify that the
    // peer key is valid by request to the server. After that we can assume the initiation is correct.
    /// Creates a new responder actor in the Double Ratchet System.
    ///
    /// Required Arguments are those as specified in Signal's Double Ratchet Protocol for the responder,
    /// Bob.
    ///
    /// This method will fail if the OTK hash does not correspond to a valid OTK.
    pub fn new(
        identity_key: PrivateKey,
        prekey: PrivateKey,
        init_bundle: &InitiatingBundle,
        key_resolver: &mut impl KeyResolver,
    ) -> Result<Self, DoubleRatchetError> {

        let otk;
        if let Some(otk_hash) = init_bundle.otk_hash {
            dbg!(otk_hash);
            otk = Some(key_resolver
                .resolve_otk(otk_hash)
                .ok_or(DoubleRatchetError::NonExistentKey)?);
        } else {
            otk = None;
        }

        let mut secret_materials = [
            prekey.exchange(&init_bundle.identity_key),
            identity_key.exchange(&init_bundle.ephemeral_key),
            prekey.exchange(&init_bundle.ephemeral_key),
            if let Some (otk) = otk {
                otk.exchange(&init_bundle.ephemeral_key)
            } else {
                [0u8;32]
            }
        ]
        .concat();

        let mut secret = HashProtocol::sha256(None, &secret_materials)
            .to_hkdf()
            .expand(Some(PROTOCOL_INFO), 32)
            .try_into()
            .expect("SECRET LONGER THAN EXPECTED");
        secret_materials.zeroize();

        let core = Fundamentals::initialize(secret, identity_key, false);
        secret.zeroize();
        Ok(Self { core })
    }
}


impl PrekeyBundle {
    pub fn new(prekey: PublicKey, prekey_signature: Signature) -> Self {
        Self {
            prekey,
            prekey_signature,
        }
    }
}


/// A trait defining basic requirements for a Double Ratchet Actor.
pub trait DoubleRatchetProtocolImplementor {
    /// Encrypts a message as specified by Signal's Double Ratchet Protocol.
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage;

    /// Decrypts a message as specified by Signal's Double Ratchet Protocol.
    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError>;

    /// Getter function that determines if this Implementor was the initiator in
    /// the conversation.
    fn is_initiator(&self) -> bool;
}


/// Defines the interface for resolving keys used in the Double Ratchet exchange.
///
/// This trait should also handle the disposal of used key bundles.
pub trait KeyResolver {
    /// Resolves a Private key bundle from its Public counterpart's hash.
    ///
    /// If the key bundle is stored in persistent storage, this function should
    /// also delete its entry.
    fn resolve_otk(&mut self, hash: u64) -> Option<PrivateKey>;
}

impl DoubleRatchetProtocolImplementor for Initiator {
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage {
        self.core.send(message)
    }

    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError> {
        self.core.recv(message)
    }

    fn is_initiator(&self) -> bool {
        true
    }
}

impl DoubleRatchetProtocolImplementor for Responder {
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage {
        self.core.send(message)
    }

    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError> {
        self.core.recv(message)
    }

    fn is_initiator(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use seahash::SeaHasher;

    #[allow(unused_imports)]
    use super::*;

    /// Tests if the Double Ratchet implementation works.
    fn test_ratcheting_systems(mut initiator: Initiator, mut responder: Responder) {


        let message = initiator.send(b"Hello!");
        let second_message = initiator.send(b"How are you?");
        responder.recv(&message).unwrap();
        responder.recv(&second_message).unwrap();

        // test state reallocation
        // do not need to test state realloc on Responder since it uses
        // the same underlying method
        let message = responder.send(b"Just Fine!");
        let state = rmp_serde::to_vec(&initiator).unwrap();
        let mut new_initiator: Initiator = rmp_serde::from_slice(&state).unwrap();
        new_initiator.recv(&message).unwrap();
        
        let message = responder.send(b"Weather is cool!");
        let second_message = responder.send(b"How about you?");

        

        // test out of order messages
        let second_message = new_initiator.recv(&second_message).unwrap();
        let first_message = new_initiator.recv(&message).unwrap();
        assert_eq!(String::from_utf8(first_message).unwrap(), "Weather is cool!");
        assert_eq!(String::from_utf8(second_message).unwrap(), "How about you?");

        let mut messages = Vec::new();
        // stress testing
        for _i in 0..200 {
            messages.push(responder.send(b"Stress testing message."));
        }
        for message in messages {
            new_initiator.recv(&message).unwrap();
        }

        let mut messages = Vec::new();
        for _i in 0..200 {
            messages.push(new_initiator.send(b"Stress testing message."));
        }
        for message in messages {
            responder.recv(&message).unwrap();
        }
    }

    #[test]
    fn test_ratchet_system() {

        struct TestingResolver {
            contents: HashMap<u64, PrivateKey>
        }

        impl TestingResolver {
            fn add(&mut self, id: u64, key: PrivateKey) {
                self.contents.insert(id, key);
            }

            fn new() -> Self {
                Self {
                    contents: HashMap::new(),
                }
            }
        }

        impl KeyResolver for TestingResolver {
            fn resolve_otk(&mut self, id: u64) -> Option<PrivateKey> {
                self.contents.remove(&id)
            }
        }
        let mut resolver = TestingResolver::new();
        let responder_otk = PrivateKey::new();
        let mut hasher = SeaHasher::new();
        responder_otk.public_key().hash(&mut hasher);
        let responder_otk_hash = hasher.finish();
        dbg!(responder_otk_hash);
        resolver.add(responder_otk_hash, responder_otk.clone());
        
        let responder_identity_key = PrivateKey::new();
        let responder_prekey = PrivateKey::new();

        let responder_prekey_bundle = PrekeyBundle::new(
            responder_prekey.public_key(), 
            responder_identity_key.sign(
                &responder_prekey.public_key()
            )
        );

        let initiator_identity_key = PrivateKey::new();

        // testing handshake with otk
        let (initiator, handshake) = Initiator::new(
            initiator_identity_key.clone(),
            responder_identity_key.public_key(), 
            responder_prekey_bundle.clone(), 
            Some(responder_otk.public_key()), 
            &mut SeaHasher::new()
        ).expect("Initiator instantiation failed.");

        let responder = Responder::new(
            responder_identity_key.clone(),
            responder_prekey.clone(),
            &handshake,
            &mut resolver,
        ).expect("Responder instantiation failed.");

        test_ratcheting_systems(initiator, responder);

        // test without OTK
        let (initiator, handshake) = Initiator::new(
            initiator_identity_key,
            responder_identity_key.public_key(), 
            responder_prekey_bundle, 
            None, 
            &mut SeaHasher::new()
        ).expect("Initiator instantiation failed.");

        let responder = Responder::new(
            responder_identity_key,
            responder_prekey,
            &handshake,
            &mut resolver,
        ).expect("Responder instantiation failed.");

        test_ratcheting_systems(initiator, responder);
    }
}
