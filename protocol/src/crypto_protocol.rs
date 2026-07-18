// use crate::{
//     datatypes::{
//         Addr, CryptMessage, CryptoProtocol, DecodedMessage, HashFactory, ProtocolData
//     }, errors::IoProtocolError,
// };
// use hcrypt::{
//     double_ratchet::{
//         DoubleRatchetProtocolImplementor, InitiatingBundle, Initiator, KeyResolver,
//         PrivateKeyBundle, PublicKeyBundle, Responder,
//     },
//     key::{PrivateKey, PublicKey},
// };
// use std::{collections::HashMap};


// struct CryptoProtocolImplementor {
//     identity_key: PrivateKey,
//     conversation_map: HashMap<Addr, Box<dyn DoubleRatchetProtocolImplementor>>,
//     key_map: HashMap<u64, PrivateKeyBundle>,
//     hash_function: HashFactory,
// }

// impl KeyResolver for CryptoProtocolImplementor {
//     fn resolve_key(&mut self, hash: u64) -> Option<PrivateKeyBundle> {
//         self.key_map.remove(&hash)
//     }
// }

// impl CryptoProtocol for CryptoProtocolImplementor {

//     fn new_conversation(
//         &mut self,
//         target: &Addr,
//         peer_identity_key: PublicKey,
//         keys: &PublicKeyBundle,
//     ) -> Result<InitiatingBundle, IoProtocolError> {
//         let (conversation, handshake_data) = Initiator::new(
//             self.identity_key.clone(),
//             peer_identity_key,
//             keys,
//             &mut (&mut self.hash_function)(),
//         )?;
//         self.conversation_map
//             .insert(target.clone(), Box::new(conversation));
//         Ok(handshake_data)
//     }

//     fn resolve_conversation_request(
//         &mut self,
//         from: &Addr,
//         handshake_data: &InitiatingBundle,
//     ) -> Result<(), IoProtocolError> {
//         let conversation = Responder::new(self.identity_key.clone(), handshake_data, self)?;
//         self.conversation_map
//             .insert(from.clone(), Box::new(conversation));
//         Ok(())
//     }

//     fn decrypt_message(
//         &mut self,
//         ciphertext: ProtocolData,
//     ) -> Result<DecodedMessage, IoProtocolError> {
//         let ProtocolData::CryptMessage {ref sender, ..} = ciphertext else {
//             return Err(IoProtocolError::LogicFault { reason: "Attempted to convert non-crypt message into decoded message.".into() })
//         };
//         if let Some(conversation) = self.conversation_map.get_mut(sender) {
//             return ciphertext.crypt_msg_as_decoded(conversation);
//         }
//         Err(IoProtocolError::ConversationNotFound)
//     }

//     fn regenerate_keys(&mut self) -> Vec<PublicKeyBundle> {
//         todo!()
//     }
// }
