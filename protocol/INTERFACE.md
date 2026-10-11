# hcrypt/hcrypt-primitives/src/aes.rs ([small], 70 lines, 2093 chars, 2 methods)
/// Primitive method for encrypting data.
///
/// Encrypts data using AES-256 in GCM mode, with a randomly generated nonce that is
/// prepended to the ciphertext and zeroized after use. This does NOT zeroize the provided
/// key nor the payload, and as such care should be taken to ensure that they are effectively
/// zeroized after encryption.
...
pub fn encrypt(key: &[u8], payload: &[u8]) -> Vec<u8>  L22-39

/// primitive method for decrypting data.
///
/// decrypts data using AES-256 in GCM mode. Ciphertext must have been generated using
/// the primitive encryption function, as the ciphertext will contain nonce and authentication
/// data. Does NOT zeroize the key, so care must be taken to zeroize the key after use.
///
...
pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptionError>  L50-67


# hcrypt/hcrypt-primitives/src/errors.rs ([tiny], 30 lines, 671 chars)

# hcrypt/hcrypt-primitives/src/hkdf.rs ([tiny], 45 lines, 1243 chars, 2 types, 5 methods, 1 fields)
pub enum HashProtocol  L5-8
    Sha256  L6
    Sha512  L7
    pub fn sha256(salt:Option<&[u8]>, ikm: &[u8]) -> Self  L15
    pub fn sha512(salt:Option<&[u8]>, ikm: &[u8]) -> Self  L16
    pub fn to_hkdf(self) -> HKDF  L17
    fn expand(&self, info:Option<&[u8]>, len:usize) -> Vec<u8>  L20-38

pub struct HKDF  L10-12
    protocol:HashProtocol  L11
    pub fn expand(&self, info: Option<&[u8]>, len: usize) -> Vec<u8>  L42-44


# hcrypt/hcrypt-primitives/src/kdf.rs ([small], 52 lines, 1448 chars, 2 methods)
/// Generates a 256 bit key for encryption.
///
/// uses Argon2 to create a cryptographically strong encryption key.
///
/// # Arguments
///
...
pub fn argon2( input: &[u8], salt: &[u8], ) -> Result<Vec<u8>, SymmetricKeyGenerationError>  L27-39

#[test] fn test_key_generation()  L42-51


# hcrypt/hcrypt-primitives/src/lib.rs ([tiny], 6 lines, 88 chars)
namespace aes

namespace errors

namespace kdf

namespace x25519

namespace ratchet

namespace hkdf


# hcrypt/hcrypt-primitives/src/ratchet.rs ([small], 74 lines, 1907 chars, 1 types, 3 methods, 2 fields)
/// An implementation of a KDF chain as specified by
/// Signal's Double Ratchet Protocol.
///
/// The ratchet is implemented using the HKDF algorithm.
#[serde_as] #[derive(Serialize, Deserialize)] pub struct Ratchet  L15-19
    state: [u8; 32]  L16
    #[serde_as(as = "[_; 64]")] hkdf_buff: [u8; 64]  L18
    /// Creates a new ratchet given a key.
    ///
    /// # Arguments
    ///
    /// `key` - The 32 byte key to initiate the state with.
    ///
    ...
    pub fn new(key: [u8; RATCHET_KEY_INIT_LENGTH]) -> Self  L31-36
    /// Turn the ratchet, generating a new value.
    ///
    /// # Arguments
    ///
    /// `key_buffer` - The buffer to write the new value into. Must be of length
    /// 32.
    ...
    pub fn next(&mut self, key_buffer: &mut [u8], input: Option<&[u8]>)  L47-64
    fn zeroize(&mut self)  L68-70


# hcrypt/hcrypt-primitives/src/x25519.rs ([medium], 335 lines, 12326 chars, 1 types, 15 methods, 1 fields)
#[derive(Clone, Serialize, Deserialize)] pub struct RawPrivateKey  L33-35
    secret: StaticSecret  L34
    fn hash<H: std::hash::Hasher>(&self, state: &mut H)  L38-41
    pub fn new<R>(csprng: &mut R) -> Self where R: CryptoRng + Rng,  L45-56
    pub fn exchange(&self, peer_public_key: &[u8; PUBLIC_KEY_LENGTH]) -> [u8; AGREEMENT_LENGTH]  L58-63
    /// Calculates an XEdDSA signature using the X25519 private key directly.
    ///
    /// Refer to <https://signal.org/docs/specifications/xeddsa/#curve25519> for more details.
    ///
    /// Note that this implementation varies slightly from that paper in that the sign bit is not
    /// fixed to 0, but rather passed back in the most significant bit of the signature which would
    ...
    pub fn sign<R>(&self, csprng: &mut R, message: &[&[u8]]) -> [u8; SIGNATURE_LENGTH] where R: CryptoRng + Rng,  L73-119
    pub fn verify( their_public_key: &[u8; PUBLIC_KEY_LENGTH], message: &[&[u8]], signature: &[u8; SIGNATURE_LENGTH], ) -> bool  L121-160
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH]  L162-164
    pub fn private_key(&self) -> [u8; PRIVATE_KEY_LENGTH]  L166-168
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result  L172-177
    fn eq(&self, other: &Self) -> bool  L181-186
    fn from(private_key: [u8; 32]) -> Self  L190-193
    fn zeroize(&mut self)  L197-199

namespace tests
    #[test] fn test_agreement()  L212-250
    #[test] fn test_random_agreements()  L253-264
    #[test] fn test_signature()  L267-318
    #[test] fn test_random_signatures()  L321-333


# hcrypt/src/double_ratchet.rs ([large], 634 lines, 20862 chars, 9 types, 23 methods, 25 fields)
macro_rules! advance_ratchet  L25-29

macro_rules! switch_ratchet  L31-37

fn initialize_ratchets(initiator: bool, root: &mut Ratchet) -> (Ratchet, Ratchet)  L39-54

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Debug, PartialEq, New)] pub struct DoubleRatchetMessage  L57-62
    pub ciphertext: Vec<u8>  L58
    pub public_key: PublicKey  L59
    pub previous_chain_count: u16  L60
    pub current_chain_count: u16  L61

#[derive(Hash, PartialEq, Eq, New, Clone)] pub struct PrivateKeyBundle  L65-68
    pub prekey: PrivateKey  L66
    pub one_time_key: PrivateKey  L67

#[derive(New, Serialize, Deserialize)] pub struct InitiatingBundle  L71-75
    pub otk_hash: Option<u64>  L72
    pub identity_key: PublicKey  L73
    pub ephemeral_key: PublicKey  L74

#[derive(Clone)] pub struct PrekeyBundle  L85-88
    pub prekey: PublicKey  L86
    pub prekey_signature: Signature  L87
    pub fn new(prekey: PublicKey, prekey_signature: Signature) -> Self  L438-443

/// Shared algorithms used to execute the Double Ratchet protocol.
#[derive(Serialize, Deserialize)] pub struct Fundamentals  L92-144
    /// The Identity key of this end of the protocol.
    /// Used to provide identity authentication in the
    /// protocol.
    identity_pair: PrivateKey  L96
    /// The ratchet used to seed the send/receive ratchets.
    /// Initialized from a shared secret derives through X3DH.
    root_ratchet: Ratchet  L100
    /// The ratchet used to generate decryption key values.
    receiving_ratchet: Ratchet  L103
    /// The ratchet used to generate encryption key values.
    sending_ratchet: Ratchet  L106
    /// The current peer ratchet public key. This value is
    /// optional as it will be automatically set upon receiving
    /// the first message.
    peer_ratchet_key: Option<PublicKey>  L111
    /// The Private key used to execute ECDH handshakes with the
    /// peer's public ratchet key, maintaining forward secrecy.
    dh_ratchet_pair: PrivateKey  L115
    /// A Hashmap for housing decryption keys for lost messages.
    /// The hashmap key is comprised of the public ratchet key
    /// the provided message was encrypted with, the message number
    /// for this public key, and the decryption key for the message
    /// that corresponds to these values.
    skipped_message_keys: HashMap<(PublicKey, [u8; 2]), DecryptionKey>  L122
    /// The number of messages sent before resetting the ratchets
    /// using the shared secret derived through ECDH with the DH
    /// ratchet pair.
    number_sent: u16  L127
    /// The number of messages received before resetting the ratchets
    /// using the shared secret derived through ECDH with the DH
    /// ratchet pair.
    number_received: u16  L132
    /// The total amount of messages sent using the last ratchet set.
    /// Appended to messages to allow for the peer to skip lost messages
    /// and store their keys for later.
    prev_send_chain_num: u16  L137
    /// An owned buffer used to house ratchet keys.
    key_buff: DecryptionKey  L140
    /// State lock that prevents exporting of state more than once.
    is_initiator: bool  L143
    /// Initializes the core implementation.
    ///
    /// # Arguments
    /// `key` - The shared key to initiate the root ratchet with. Should be derived through
    /// X3DH.
    ///
    ...
    pub fn initialize( key: [u8; RATCHET_KEY_INIT_LENGTH], identity_key: PrivateKey, is_initiator: bool, ) -> Self  L171-195
    /// Executes a DH ratchet step.
    fn dh_ratchet(&mut self, message_public_key: PublicKey)  L198-213
    /// Serializes and returns a [`DoubleRatchetMessage`].
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage  L216-231
    /// Generates the decryption key for a given [`DoubleRatchetMessage`], potentially
    /// skipping keys for missed messages, and returns the the decrypted data.
    ///
    /// # Arguments
    ///
    /// `message` - the message to decrypt.
    ...
    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError>  L244-270
    /// Checks if a given message has an already present decryption key.
    fn attempt_decrypt_with_stored_keys( &mut self, message: &DoubleRatchetMessage, ) -> Result<Option<Vec<u8>>, DecryptionError>  L273-287
    /// Skips a given amount of message keys.
    ///
    /// Will return an Error if the amount of keys exceeds the max message
    /// queue.
    fn skip_message_keys(&mut self, until: &u16) -> Result<(), DoubleRatchetError>  L293-316
    fn zero_buffers(&mut self)  L318-320

/// An implementation of the Double Ratchet protocol designed to
/// accept double ratchet conversations.
#[derive(Serialize, Deserialize)] pub struct Initiator  L149-151
    core: Fundamentals  L150
    /// Creates a new Initiator actor.
    ///
    /// Required arguments are those as specified in Signals X3DH protocol
    /// using one time keys for the initiator in the protocol, Alice.
    ///
    /// This method may return a Crate Error if the prekey public key signature is
    ...
    pub fn new( identity_key: PrivateKey, peer_identity_key: PublicKey, peer_prekey: PrekeyBundle, otk: Option<PublicKey>, hasher: &mut impl Hasher, ) -> Result<(Self, InitiatingBundle), DecryptionError>  L335-382
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage  L473-475
    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError>  L477-479
    fn is_initiator(&self) -> bool  L481-483

/// An implementation of the Double Ratchet protocol designed to
/// request double ratchet conversations.
#[derive(Serialize, Deserialize)] pub struct Responder  L156-158
    core: Fundamentals  L157
    /// Creates a new responder actor in the Double Ratchet System.
    ///
    /// Required Arguments are those as specified in Signal's Double Ratchet Protocol for the responder,
    /// Bob.
    ///
    /// This method will fail if the OTK hash does not correspond to a valid OTK.
    pub fn new( identity_key: PrivateKey, prekey: PrivateKey, init_bundle: &InitiatingBundle, key_resolver: &mut impl KeyResolver, ) -> Result<Self, DoubleRatchetError>  L394-433
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage  L487-489
    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError>  L491-493
    fn is_initiator(&self) -> bool  L495-497

/// A trait defining basic requirements for a Double Ratchet Actor.
pub trait DoubleRatchetProtocolImplementor  L448-458
    /// Encrypts a message as specified by Signal's Double Ratchet Protocol.
    fn send(&mut self, message: &[u8]) -> DoubleRatchetMessage  L450
    /// Decrypts a message as specified by Signal's Double Ratchet Protocol.
    fn recv(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError>  L453
    /// Getter function that determines if this Implementor was the initiator in
    /// the conversation.
    fn is_initiator(&self) -> bool  L457

/// Defines the interface for resolving keys used in the Double Ratchet exchange.
///
/// This trait should also handle the disposal of used key bundles.
pub trait KeyResolver  L464-470
    /// Resolves a Private key bundle from its Public counterpart's hash.
    ///
    /// If the key bundle is stored in persistent storage, this function should
    /// also delete its entry.
    fn resolve_otk(&mut self, hash: u64) -> Option<PrivateKey>  L469

namespace tests
    /// Tests if the Double Ratchet implementation works.
    fn test_ratcheting_systems(mut initiator: Initiator, mut responder: Responder)  L508-551
    #[test] fn test_ratchet_system()  L554-632


# hcrypt/src/ecies.rs ([small], 163 lines, 5360 chars, 2 methods)
/// Encrypts byte data through an ECIES protocol.
///
/// Uses a 32 byte public key as the encryption key, and a provided private key as
/// the signing key.
///
/// If the internal key generation done after the Elliptic Curve Diffie Hellman Exchange
...
pub fn ecies_encrypt( encryption_key: &PublicKey, signing_key: &PrivateKey, data: &[u8], ) -> Result<Vec<u8>, SymmetricKeyGenerationError>  L63-89

/// Decrypts a generated ciphertext through an ECIES protocol.
///
/// Uses a provided private key for decryption; this must be the private analogue to the
/// public key used for encryption. Additionally uses a provided public key for verification;
/// this must be the public analogue to the private key used for signing.
///
...
pub fn ecies_decrypt( decryption_key: &PrivateKey, verification_key: &[u8; 32], ciphertext: &[u8], ) -> Result<Vec<u8>, DecryptionError>  L135-162


# hcrypt/src/key.rs ([small], 98 lines, 2745 chars, 1 types, 9 methods, 1 fields)
/// An implementation of a XEd25519 key.
///
/// The XEd25519 implementation allows for the support of signing, verifying, and ECDH.
#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Clone)] pub struct PrivateKey  L11-13
    private_key: RawPrivateKey  L12
    fn default() -> Self  L23-25
    /// creates a new key from a given scalar.
    ///
    /// consumes the scalar.
    pub fn load(key: [u8; PRIVATE_KEY_LENGTH]) -> Self  L32-36
    /// Generates a new private key.
    pub fn new() -> Self  L39-43
    /// Returns the public counterpart to this key.
    pub fn public_key(&self) -> PublicKey  L46-48
    /// Performs a ECDH exchange with a given peer key.
    ///
    /// # Arguments
    ///
    /// `peer_key` - The public key of the other party. Must be 32 bytes long.
    pub fn exchange(&self, peer_key: &PublicKey) -> KeyExchangeSecret  L55-57
    /// Signs data with this key for verification purposes.
    ///
    /// # Arguments
    ///
    /// `data` - The data to sign.
    ///
    ...
    pub fn sign(&self, data: &[u8]) -> Signature  L68-70
    /// Verifies from a peer given their public key.
    ///
    /// # Arguments
    ///
    /// `peer_key` - The key to verify with, as a [u8] slice of length 32.
    ///
    ...
    pub fn verify(peer_key: &PublicKey, data: &[u8], signature: &Signature) -> bool  L81-83
    /// Returns the private scalar value as a vector of length 32.
    pub fn private_key(&self) -> ExportedPrivateKey  L86-88
    fn from(value: RawPrivateKey) -> Self  L92-96


# hcrypt/src/lib.rs ([tiny], 7 lines, 113 chars)
namespace ecies

namespace key

namespace double_ratchet

namespace errors


# src/crypto_protocol.rs ([small], 76 lines, 2575 chars)

# src/datatypes.rs ([small], 88 lines, 2492 chars, 5 types, 3 methods, 6 fields)
#[derive(Debug)] pub struct CryptMessage  L18-22
    pub payload: DoubleRatchetMessage  L19
    pub datatype: MessageType  L20
    pub sender: Addr  L21
    pub fn self_as_protocol_data(self) -> ProtocolData  L81-87

pub struct DecodedMessage  L24-28
    pub payload: Vec<u8>  L25
    pub datatype: MessageType  L26
    pub sender: Addr  L27

#[derive(Debug, Clone, Serialize, Deserialize)] pub enum MessageType  L31-34
    Text  L32
    Image  L33

#[derive(Serialize, Deserialize)] pub enum ProtocolData  L37-48
    InitiatingBundle  L38-41
    CryptMessage  L42-46
    Null  L47
    pub fn crypt_msg_as_decoded(&self, receiver: &mut Box<dyn DoubleRatchetProtocolImplementor>, ) -> Result<DecodedMessage, ProtocolError>  L57-70
    pub fn self_as_crypt_msg(self) -> Result<CryptMessage, ProtocolError>  L72-77

pub enum TimeData  L50-52
    PrekeyRotation  L51


# src/errors.rs ([tiny], 36 lines, 987 chars)

# src/lib.rs ([tiny], 7 lines, 114 chars)
namespace protocol

namespace crypto_protocol

namespace datatypes

namespace errors

namespace networking

namespace traits


# src/networking.rs ([small], 87 lines, 2471 chars, 6 types, 3 methods)
#[derive(Debug)] pub enum DbQuery  L36-40
    IdentityKey  L37
    Prekey  L38
    Otk  L39

pub enum DBData  L42-46
    IdentityKey  L43
    Prekey  L44
    Otk  L45

pub enum DbWrite  L48-50
    Prekey  L49

impl TryFrom<DBData> for PublicKey  L52-62
    fn try_from(value: DBData) -> Result<Self, Self::Error>  L55-61

impl TryFrom<DBData> for PrekeyBundle  L64-74
    fn try_from(value: DBData) -> Result<Self, Self::Error>  L67-73

impl TryFrom<DBData> for Option<PublicKey>  L76-86
    fn try_from(value: DBData) -> Result<Self, Self::Error>  L79-85


# src/protocol.rs ([medium], 228 lines, 7845 chars, 2 types, 9 methods, 8 fields)
struct DbResponseHandler  L12-15
    and_then: Box<dyn FnMut(Vec<DBData>) -> Result<(), ProtocolError>>  L13
    timeout: Box<dyn Fn() -> Result<(), ProtocolError>>  L14
    pub fn new( and_then: Box<dyn FnMut(Vec<DBData>) -> Result<(), ProtocolError>>, timeout: Box<dyn Fn() -> Result<(), ProtocolError>>, ) -> Self  L18-23

pub struct HermesProtocol  L26-33
    user: Rc<Addr>  L27
    request_mapper: HashMap<RequestID, DbResponseHandler>  L28
    database_protocol: Box<dyn DbAccessProtocol>  L29
    data_serving_protocol: Rc<dyn DataServer>  L30
    interface_protocol: Box<dyn UserInterface>  L31
    conversation_protocol: Rc<RefCell<dyn CryptoProtocol>>  L32
    pub fn new( whoami: Addr, conversation_protocol: Rc<RefCell<dyn CryptoProtocol>>, database_protocol: Box<dyn DbAccessProtocol>, data_serving_protocol: Rc<dyn DataServer>, interface_protocol: Box<dyn UserInterface>, ) -> Self  L37-52
    pub fn inbound_data(&mut self, data: ProtocolData)  L58-100
    pub fn resolve(&mut self, query_id: RequestID, data: Vec<DBData>, timed_out: bool)  L102-107
    pub fn create_new_conversation(&mut self, target: Addr)  L113-155
    pub fn send_message(&mut self, who: &Addr, message: DecodedMessage)  L157-175
    pub fn delete_conversation(&mut self, who: &Addr)  L177-185
    pub fn new_event(&mut self, event: TimeData)  L190-202
    fn resolve_internal( &mut self, query_id: RequestID, data: Vec<DBData>, timed_out: bool, ) -> Result<(), ProtocolError>  L207-226


# src/traits.rs ([small], 63 lines, 1815 chars, 6 types, 18 methods)
pub trait DbQueryBuilder  L8-11
    fn add(&mut self, query: DbQuery) -> &mut dyn DbQueryBuilder  L9
    fn execute(&mut self) -> RequestID  L10

pub trait DbWriteBuilder  L13-16
    fn add(&mut self, data: DbWrite) -> &mut dyn DbWriteBuilder  L14
    fn write_or_cache(&mut self)  L15

pub trait DbAccessProtocol  L20-23
    fn query_db(&self) -> Box<dyn DbQueryBuilder>  L21
    fn write_db(&self) -> Box<dyn DbWriteBuilder>  L22

pub trait DataServer  L25-27
    fn send_else_cache_data(&self, data: ProtocolData)  L26

pub trait CryptoProtocol  L29-58
    fn new_conversation( &mut self, target: &Addr, peer_identity_key: PublicKey, prekey: &PrekeyBundle, otk: &Option<PublicKey>, ) -> Result<InitiatingBundle, ProtocolError>  L30-36
    fn delete_conversation(&mut self, target: &Addr) -> Result<(), ProtocolError>  L38
    fn resolve_conversation_request( &mut self, from: &Addr, handshake_data: &InitiatingBundle, ) -> Result<(), ProtocolError>  L40-44
    fn send_message(&mut self, target: &Addr, message: DecodedMessage) -> Result<CryptMessage, ProtocolError>  L46
    fn decrypt_message( &mut self, ciphertext: CryptMessage, ) -> Result<DecodedMessage, ProtocolError>  L48-51
    fn rotate_prekey(&mut self) -> (PublicKey, Signature)  L53
    fn check_keys(&self) -> usize  L55
    fn conversation_exists(&self, target: &Addr) -> bool  L56
    fn generate_keys(&mut self, count: usize) -> Vec<PrekeyBundle>  L57

pub trait UserInterface  L60-63
    fn new_message(&mut self, message: DecodedMessage)  L61
    fn protocol_error(&mut self, err: &ProtocolError)  L62


