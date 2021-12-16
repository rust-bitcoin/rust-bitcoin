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
use bech32;

use hashes::{sha256, sha256d, Hash, HashEngine};

use blockdata::opcodes;
use consensus::{encode, Encodable};


use util::address::{Address, Payload};

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
    use util::address::{Address};

    use util::misc::{bech32_decode, segwit_redeem_hash, hash160, get_payload_bytes};

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

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum SegwitType {
        P2wpkh,
        P2shwpkh
    }

    impl SegwitType {
        pub fn from_flag_byte(byte: u8) -> Option<SegwitType> {
            if (byte & 8) == 0 {
                None
            } else if (byte & 4) == 0 {
                Some(SegwitType::P2shwpkh)
            } else {
                Some(SegwitType::P2wpkh)
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
        /// Segwit type realted to this signature
        pub segwit_type: Option<SegwitType>,
        /// Recovery Id for easy access
        pub recovery_id: RecoveryId,
    }

    impl MessageSignature {
        /// Create a new [MessageSignature].
        pub fn new(signature: RecoverableSignature, compressed: bool, segwit_type: Option<SegwitType>) -> MessageSignature {
            MessageSignature {
                signature: signature,
                compressed: compressed,
                segwit_type,
                recovery_id: signature.serialize_compact().0,
            }
        }

        /// Serialize to bytes.
        pub fn serialize(&self) -> [u8; 65] {
            let (recovery_id, raw) = self.signature.serialize_compact();
            let mut serialized = [0u8; 65];
            serialized[0] = 27;
            serialized[0] += recovery_id.to_i32() as u8;
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
            // array access safe because of the check above
            let flag_byte = bytes[0]
                .checked_sub(27)
                .ok_or(MessageSignatureError::InvalidEncoding(secp256k1::Error::InvalidRecoveryId))?;
            let recovery_id = RecoveryId::from_i32((flag_byte & 0x03) as i32)?;
            Ok(MessageSignature {
                signature: RecoverableSignature::from_compact(&bytes[1..], recovery_id)?,
                compressed: (flag_byte & 12) != 0,
                segwit_type: SegwitType::from_flag_byte(flag_byte),
                recovery_id,
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
            // Mostly ported from: https://github.com/bitcoinjs/bitcoinjs-message/blob/c43430f4c03c292c719e7801e425d887cbdf7464/index.js#L181-L233
            let pubkey = self.recover_pubkey(&secp_ctx, msg_hash)?;

            let pubkey_hash = pubkey.pubkey_hash();

            match self.segwit_type {
                None => {
                    let expected = match bech32_decode(address) {
                        Ok(data) => data,
                        Err(_) => {
                            let redeem_hash = segwit_redeem_hash(&pubkey_hash);
                            let base58_check = get_payload_bytes(address);
                            return Ok(
                                (*pubkey_hash == *base58_check) ||
                                (*redeem_hash == *base58_check)
                            );
                        }
                    };
                    Ok(*pubkey_hash == *expected)
                },
                Some(SegwitType::P2shwpkh) => {
                    let actual = segwit_redeem_hash(&pubkey_hash);
                    let expected = get_payload_bytes(address);
                    Ok(*actual == *expected)
                },
                Some(SegwitType::P2wpkh) => {
                    let expected = bech32_decode(address).unwrap();
                    Ok(*pubkey_hash == *expected)
                },
            }
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

/// Ripemd160 hash of sha256 hash of given data
pub fn hash160(data: &[u8]) -> ::hashes::hash160::Hash {
    let mut sha_engine = sha256::Hash::engine();
    sha_engine.input(data);

    ::hashes::hash160::Hash::from_engine(sha_engine)
}

/// Convert a byte array of a pubkey hash into a segwit redeem hash
pub fn segwit_redeem_hash(pubkey_hash: &[u8]) -> ::hashes::hash160::Hash {
    let mut sha_engine = sha256::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash);
    ::hashes::hash160::Hash::from_engine(sha_engine)
}

/// Pull out payload as byte array
pub fn get_payload_bytes(address: &Address) -> &[u8] {
    match &address.payload {
        Payload::ScriptHash(hash) => &hash,
        Payload::PubkeyHash(hash) => &hash,
        Payload::WitnessProgram { program, .. } => &program,
    }
}

#[derive(Debug, PartialEq, Eq)]
/// Errors from failures to decode bech32
pub enum Bech32DecodingError {
    /// Excessive padding when converting Vec<u5> to Vec<u8>
    ExcessivePadding,
    /// Non-zero padding when converting Vec<u5> to Vec<u8>
    NonZeroPadding,
    /// The Bech32 is invalidly encoded
    InvalidEncoding(bech32::Error),
}

/// decode address to Bech32 u8 byte array
pub fn bech32_decode(address: &Address) -> Result<Vec<u8>, Bech32DecodingError> {
    match bech32::decode(&address.to_string()) {
        Ok((_, u5_vec, _)) => bech32_from_words(&u5_vec[1..]),
        Err(e) => Err(Bech32DecodingError::InvalidEncoding(e))
    }
}

/// Convert u5 vec into u8 vec
fn bech32_from_words(words: &[bech32::u5]) -> Result<Vec<u8>, Bech32DecodingError> {
    let in_bits: i32 = 5;
    let out_bits: i32 = 8;

    let mut value: i32 = 0;
    let mut bits: i32 = 0;
    let max_v: i32 = 255;

    let mut out: Vec<u8> = Vec::new();
    for word in words.iter().map(|x| x.to_u8()) {
        value = (value << in_bits) | (word as i32);
        bits += in_bits;
        while bits >= out_bits {
            bits -= out_bits;
            out.push(((value >> bits) & max_v) as u8);
        }
    }
    if bits >= in_bits {
        return Err(Bech32DecodingError::ExcessivePadding);
    }
    if ((value << (out_bits - bits)) & max_v) != 0 {
        return Err(Bech32DecodingError::NonZeroPadding);
    }
    Ok(out)
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
        use secp256k1::recovery::RecoveryId;

        let secp = secp256k1::Secp256k1::new();
        let message = "rust-bitcoin MessageSignature test";
        let msg_hash = super::signed_msg_hash(&message);
        let msg = secp256k1::Message::from_slice(&msg_hash).unwrap();

        let privkey = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
        let secp_sig = secp.sign_recoverable(&msg, &privkey);
        let signature = super::MessageSignature {
            signature: secp_sig,
            compressed: true,
            recovery_id: RecoveryId::from_i32(0).unwrap(),
            segwit_type: None,
        };

        assert_eq!(signature.to_base64(), signature.to_string());
        let signature2 = super::MessageSignature::from_str(&signature.to_string()).unwrap();
        let pubkey = signature2.recover_pubkey(&secp, msg_hash).unwrap();
        assert_eq!(pubkey.compressed, true);
        assert_eq!(pubkey.key, secp256k1::PublicKey::from_secret_key(&secp, &privkey));

        let p2pkh = ::Address::p2pkh(&pubkey, ::Network::Bitcoin);
        assert_eq!(signature2.is_signed_by_address(&secp, &p2pkh, msg_hash), Ok(true));
        let p2wpkh = ::Address::p2wpkh(&pubkey, ::Network::Bitcoin).unwrap();
        assert_eq!(signature2.is_signed_by_address(&secp, &p2wpkh, msg_hash), Ok(true));
        let p2shwpkh = ::Address::p2shwpkh(&pubkey, ::Network::Bitcoin).unwrap();
        assert_eq!(signature2.is_signed_by_address(&secp, &p2shwpkh, msg_hash), Ok(true));
    }

    #[cfg(all(feature = "secp-recovery"))]
    mod is_signed_by_address {
        use secp256k1;
        use std::str::FromStr;

        use hashes::hex::FromHex;
        use super::super::MessageSignature;
        use util::address::Address;
        use util::misc::signed_msg_hash;

        #[test]
        fn test_p2wpkh() {
            let message_string = "test message to sign".to_string();
            let message_hash = signed_msg_hash(&message_string);

            let address_string = "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4".to_string();
            let address = Address::from_str(&address_string).unwrap();

            let sig_string = "286b079e6f3d74a83b5b90710a803f54a1d8c0beb7abaa1b9a5b26f100ef36e8f25d6f7eb73f10eaaac4fe725cb2901f60b890009f93318c7df4836df3b22b9901".to_string();
            let sig_bytes = <Vec<u8>>::from_hex(&sig_string).unwrap();
            let message_signature = MessageSignature::from_slice(&sig_bytes).unwrap();

            let secp_ctx = secp256k1::Secp256k1::new();

            let result = message_signature.is_signed_by_address(&secp_ctx, &address, message_hash);
            assert!(result.unwrap());
        }

        #[test]
        fn test_p2shwpkh() {
            let message_string = "test message to sign".to_string();
            let message_hash = signed_msg_hash(&message_string);

            let address_string = "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs".to_string();
            let address = Address::from_str(&address_string).unwrap();

            let sig_string = "246b079e6f3d74a83b5b90710a803f54a1d8c0beb7abaa1b9a5b26f100ef36e8f25d6f7eb73f10eaaac4fe725cb2901f60b890009f93318c7df4836df3b22b9901".to_string();
            let sig_bytes = <Vec<u8>>::from_hex(&sig_string).unwrap();
            let message_signature = MessageSignature::from_slice(&sig_bytes).unwrap();

            let secp_ctx = secp256k1::Secp256k1::new();

            let result = message_signature.is_signed_by_address(&secp_ctx, &address, message_hash);
            assert!(result.unwrap());
        }

        #[test]
        fn test_p2pkh() {
            let message_string = "test message to sign".to_string();
            let message_hash = signed_msg_hash(&message_string);

            let address_string = "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx".to_string();
            let address = Address::from_str(&address_string).unwrap();

            let sig_string = "206b079e6f3d74a83b5b90710a803f54a1d8c0beb7abaa1b9a5b26f100ef36e8f25d6f7eb73f10eaaac4fe725cb2901f60b890009f93318c7df4836df3b22b9901".to_string();
            let sig_bytes = <Vec<u8>>::from_hex(&sig_string).unwrap();
            let message_signature = MessageSignature::from_slice(&sig_bytes).unwrap();

            let secp_ctx = secp256k1::Secp256k1::new();

            let result = message_signature.is_signed_by_address(&secp_ctx, &address, message_hash);
            assert!(result.unwrap());
        }

        #[test]
        fn test_p2pkh_2() {
            // Testcase that was failing the first iteration
            // due to incorrectly setting MessageSignature.compressed
            // when using MessageSignature::from_slice
            let message_string = "23a1c49208661ef362f941dcf84e156fmsvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6pe6f20d12-14da-4dd0-b058-e8d3c9e821f0".to_string();
            let message_hash = signed_msg_hash(&message_string);

            let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p".to_string();
            let address = Address::from_str(&address_string).unwrap();

            let sig_string = "1c2b156b7634c8facfc32100d45424e619e66be1f816b20dffecbe57e9714623c97181c3d3f558a48825b5c26804ee37aa775bea7f906d7a6144aa239962b0a0a9".to_string();
            let sig_bytes = <Vec<u8>>::from_hex(&sig_string).unwrap();
            let message_signature = MessageSignature::from_slice(&sig_bytes).unwrap();

            let secp_ctx = secp256k1::Secp256k1::new();

            let result = message_signature.is_signed_by_address(&secp_ctx, &address, message_hash);
            assert!(result.unwrap());
        }
    }
}

