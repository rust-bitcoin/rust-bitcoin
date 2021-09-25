// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Miscellaneous functions
//!
//! Various utility functions

use prelude::*;

use hashes::{sha256d, Hash, HashEngine};

use blockdata::opcodes;
use consensus::{encode, Encodable};

#[cfg(feature = "secp-recovery")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp-recovery")))]
pub use self::message_signing::{MessageSignature, MessageSignatureError};

/// The prefix for signed messages using Bitcoin's message signing protocol.
pub const BITCOIN_SIGNED_MSG_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

#[cfg(feature = "secp-recovery")]
mod message_signing {
    #[cfg(feature = "base64")] use prelude::*;
    use core::fmt;
    #[cfg(feature = "std")] use std::error;

    use hashes::sha256d;
    use secp256k1;
    use secp256k1::recovery::{RecoveryId, RecoverableSignature};

    use util::ecdsa::PublicKey;
    use util::address::{Address, AddressType};

    /// An error used for dealing with Bitcoin Signed Messages.
    #[cfg_attr(docsrs, doc(cfg(feature = "secp-recovery")))]
    #[derive(Debug, PartialEq, Eq)]
    pub enum MessageSignatureError {
        /// Signature is expected to be 65 bytes.
        InvalidLength,
        /// The signature is invalidly constructed.
        InvalidEncoding(secp256k1::Error),
        /// Invalid base64 encoding.
        InvalidBase64,
    }

    impl fmt::Display for MessageSignatureError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                MessageSignatureError::InvalidLength => write!(f, "length not 65 bytes"),
                MessageSignatureError::InvalidEncoding(ref e) => write!(f, "invalid encoding: {}", e),
                MessageSignatureError::InvalidBase64 => write!(f, "invalid base64"),
            }
        }
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    impl error::Error for MessageSignatureError {
        fn cause(&self) -> Option<&dyn error::Error> {
            match *self {
                MessageSignatureError::InvalidEncoding(ref e) => Some(e),
                _ => None,
            }
        }
    }

    #[doc(hidden)]
    impl From<secp256k1::Error> for MessageSignatureError {
        fn from(e: secp256k1::Error) -> MessageSignatureError {
            MessageSignatureError::InvalidEncoding(e)
        }
    }

    /// A signature on a Bitcoin Signed Message.
    ///
    /// In order to use the `to_base64` and `from_base64` methods, as well as the
    /// `fmt::Display` and `str::FromStr` implementations, the `base64` feature
    /// must be enabled.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "secp-recovery")))]
    pub struct MessageSignature {
        /// The inner recoverable signature.
        pub signature: RecoverableSignature,
        /// Whether or not this signature was created with a compressed key.
        pub compressed: bool,
    }

    impl MessageSignature {
        /// Create a new [MessageSignature].
        pub fn new(signature: RecoverableSignature, compressed: bool) -> MessageSignature {
            MessageSignature {
                signature: signature,
                compressed: compressed,
            }
        }

        /// Serialize to bytes.
        pub fn serialize(&self) -> [u8; 65] {
            let (recid, raw) = self.signature.serialize_compact();
            let mut serialized = [0u8; 65];
            serialized[0] = 27;
            serialized[0] += recid.to_i32() as u8;
            if self.compressed {
                serialized[0] += 4;
            }
            serialized[1..].copy_from_slice(&raw[..]);
            serialized
        }

        /// Create from a byte slice.
        pub fn from_slice(bytes: &[u8]) -> Result<MessageSignature, MessageSignatureError> {
            if bytes.len() != 65 {
                return Err(MessageSignatureError::InvalidLength);
            }
            // We just check this here so we can safely subtract further.
            if bytes[0] < 27 {
                return Err(MessageSignatureError::InvalidEncoding(secp256k1::Error::InvalidRecoveryId));
            };
            let recid = RecoveryId::from_i32(((bytes[0] - 27) & 0x03) as i32)?;
            Ok(MessageSignature {
                signature: RecoverableSignature::from_compact(&bytes[1..], recid)?,
                compressed: ((bytes[0] - 27) & 0x04) != 0,
            })
        }

        /// Attempt to recover a public key from the signature and the signed message.
        ///
        /// To get the message hash from a message, use [super::signed_msg_hash].
        pub fn recover_pubkey<C: secp256k1::Verification>(
            &self,
            secp_ctx: &secp256k1::Secp256k1<C>,
            msg_hash: sha256d::Hash
        ) -> Result<PublicKey, secp256k1::Error> {
            let msg = secp256k1::Message::from_slice(&msg_hash[..])?;
            let pubkey = secp_ctx.recover(&msg, &self.signature)?;
            Ok(PublicKey {
                key: pubkey,
                compressed: self.compressed,
            })
        }

        /// Verify that the signature signs the message and was signed by the given address.
        ///
        /// To get the message hash from a message, use [super::signed_msg_hash].
        pub fn is_signed_by_address<C: secp256k1::Verification>(
            &self,
            secp_ctx: &secp256k1::Secp256k1<C>,
            address: &Address,
            msg_hash: sha256d::Hash
        ) -> Result<bool, secp256k1::Error> {
            let pubkey = self.recover_pubkey(&secp_ctx, msg_hash)?;
            Ok(match address.address_type() {
                Some(AddressType::P2pkh) => {
                    *address == Address::p2pkh(&pubkey, address.network)
                }
                Some(AddressType::P2sh) => false,
                Some(AddressType::P2wpkh) => false,
                Some(AddressType::P2wsh) => false,
                Some(AddressType::P2tr) => false,
                None => false,
            })
        }

        #[cfg(feature = "base64")]
        #[cfg_attr(docsrs, doc(cfg(feature = "base64")))]
        /// Convert a signature from base64 encoding.
        pub fn from_base64(s: &str) -> Result<MessageSignature, MessageSignatureError> {
            let bytes = ::base64::decode(s).map_err(|_| MessageSignatureError::InvalidBase64)?;
            MessageSignature::from_slice(&bytes)
        }

        #[cfg(feature = "base64")]
        #[cfg_attr(docsrs, doc(cfg(feature = "base64")))]
        /// Convert to base64 encoding.
        pub fn to_base64(&self) -> String {
            ::base64::encode(&self.serialize()[..])
        }
    }

    #[cfg(feature = "base64")]
    #[cfg_attr(docsrs, doc(cfg(feature = "base64")))]
    impl fmt::Display for MessageSignature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let bytes = self.serialize();
            // This avoids the allocation of a String.
            write!(f, "{}", ::base64::display::Base64Display::with_config(
                    &bytes[..], ::base64::STANDARD))
        }
    }

    #[cfg(feature = "base64")]
    #[cfg_attr(docsrs, doc(cfg(feature = "base64")))]
    impl ::core::str::FromStr for MessageSignature {
        type Err = MessageSignatureError;
        fn from_str(s: &str) -> Result<MessageSignature, MessageSignatureError> {
            MessageSignature::from_base64(s)
        }
    }
}

/// Search for `needle` in the vector `haystack` and remove every
/// instance of it, returning the number of instances removed.
/// Loops through the vector opcode by opcode, skipping pushed data.
pub fn script_find_and_remove(haystack: &mut Vec<u8>, needle: &[u8]) -> usize {
    if needle.len() > haystack.len() { return 0; }
    if needle.is_empty() { return 0; }

    let mut top = haystack.len() - needle.len();
    let mut n_deleted = 0;

    let mut i = 0;
    while i <= top {
        if &haystack[i..(i + needle.len())] == needle {
            for j in i..top {
                haystack.swap(j + needle.len(), j);
            }
            n_deleted += 1;
            // This is ugly but prevents infinite loop in case of overflow
            let overflow = top < needle.len();
            top = top.wrapping_sub(needle.len());
            if overflow { break; }
        } else {
            i += match opcodes::All::from((*haystack)[i]).classify(opcodes::ClassifyContext::Legacy) {
                opcodes::Class::PushBytes(n) => n as usize + 1,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => 2,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => 3,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => 5,
                _ => 1
            };
        }
    }
    haystack.truncate(top.wrapping_add(needle.len()));
    n_deleted
}

/// Hash message for signature using Bitcoin's message signing format.
pub fn signed_msg_hash(msg: &str) -> sha256d::Hash {
    let mut engine = sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    let msg_len = encode::VarInt(msg.len() as u64);
    msg_len.consensus_encode(&mut engine).unwrap();
    engine.input(msg.as_bytes());
    sha256d::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {
    use hashes::hex::ToHex;
    use super::script_find_and_remove;
    use super::signed_msg_hash;

    #[test]
    fn test_script_find_and_remove() {
        let mut v = vec![101u8, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109];

        assert_eq!(script_find_and_remove(&mut v, &[]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 105]), 0);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109]);

        assert_eq!(script_find_and_remove(&mut v, &[105, 106, 107]), 1);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 108, 109]);

        assert_eq!(script_find_and_remove(&mut v, &[104, 108, 109]), 1);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[101]), 1);
        assert_eq!(v, vec![102, 103, 104, 102, 103, 104, 102, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[102]), 3);
        assert_eq!(v, vec![103, 104, 103, 104, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[103, 104]), 2);
        assert_eq!(v, vec![103]);

        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 5]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[103]), 1);
        assert_eq!(v, Vec::<u8>::new());

        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 5]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105]), 0);
    }

    #[test]
    fn test_script_codesep_remove() {
        let mut s = vec![33u8, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 81];
        assert_eq!(script_find_and_remove(&mut s, &[171]), 2);
        assert_eq!(s, vec![33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 81]);
    }

    #[test]
    fn test_signed_msg_hash() {
        let hash = signed_msg_hash("test");
        assert_eq!(hash.to_hex(), "a6f87fe6d58a032c320ff8d1541656f0282c2c7bfcc69d61af4c8e8ed528e49c");
    }

    #[test]
    #[cfg(all(feature = "secp-recovery", feature = "base64"))]
    fn test_message_signature() {
        use core::str::FromStr;
        use secp256k1;

        let secp = secp256k1::Secp256k1::new();
        let message = "rust-bitcoin MessageSignature test";
        let msg_hash = super::signed_msg_hash(&message);
        let msg = secp256k1::Message::from_slice(&msg_hash).unwrap();

        let privkey = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
        let secp_sig = secp.sign_recoverable(&msg, &privkey);
        let signature = super::MessageSignature {
            signature: secp_sig,
            compressed: true,
        };

        assert_eq!(signature.to_base64(), signature.to_string());
        let signature2 = super::MessageSignature::from_str(&signature.to_string()).unwrap();
        let pubkey = signature2.recover_pubkey(&secp, msg_hash).unwrap();
        assert_eq!(pubkey.compressed, true);
        assert_eq!(pubkey.key, secp256k1::PublicKey::from_secret_key(&secp, &privkey));

        let p2pkh = ::Address::p2pkh(&pubkey, ::Network::Bitcoin);
        assert_eq!(signature2.is_signed_by_address(&secp, &p2pkh, msg_hash), Ok(true));
        let p2wpkh = ::Address::p2wpkh(&pubkey, ::Network::Bitcoin).unwrap();
        assert_eq!(signature2.is_signed_by_address(&secp, &p2wpkh, msg_hash), Ok(false));
        let p2shwpkh = ::Address::p2shwpkh(&pubkey, ::Network::Bitcoin).unwrap();
        assert_eq!(signature2.is_signed_by_address(&secp, &p2shwpkh, msg_hash), Ok(false));
    }
}

