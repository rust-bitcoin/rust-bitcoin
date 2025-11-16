// SPDX-License-Identifier: CC0-1.0

//! A signature.
//!
//! This module provides signature related functions including secp256k1 signature recovery when
//! library is used with the `secp-recovery` feature.

use hashes::{sha256d, HashEngine};
#[cfg(feature = "secp-recovery")]
use secp256k1::SecretKey;

use crate::consensus::encode::WriteExt;

#[rustfmt::skip]
#[doc(inline)]
#[cfg(feature = "secp-recovery")]
pub use self::message_signing::{MessageSignature, MessageSignatureError};

/// The prefix for signed messages using Bitcoin's message signing protocol.
pub const BITCOIN_SIGNED_MSG_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

#[cfg(feature = "secp-recovery")]
mod message_signing {
    use core::convert::Infallible;
    use core::fmt;

    use hashes::sha256d;
    use internals::write_err;
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

    use crate::address::{Address, AddressType};
    use crate::crypto::key::PublicKey;

    /// An error used for dealing with Bitcoin Signed Messages.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum MessageSignatureError {
        /// Signature is expected to be 65 bytes.
        InvalidLength,
        /// The signature is invalidly constructed.
        InvalidEncoding(secp256k1::Error),
        /// Invalid base64 encoding.
        InvalidBase64,
        /// Unsupported Address Type
        UnsupportedAddressType(AddressType),
    }

    impl From<Infallible> for MessageSignatureError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for MessageSignatureError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use MessageSignatureError::*;

            match *self {
                InvalidLength => write!(f, "length not 65 bytes"),
                InvalidEncoding(ref e) => write_err!(f, "invalid encoding"; e),
                InvalidBase64 => write!(f, "invalid base64"),
                UnsupportedAddressType(ref address_type) =>
                    write!(f, "unsupported address type: {}", address_type),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for MessageSignatureError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use MessageSignatureError::*;

            match *self {
                InvalidEncoding(ref e) => Some(e),
                InvalidLength | InvalidBase64 | UnsupportedAddressType(_) => None,
            }
        }
    }

    impl From<secp256k1::Error> for MessageSignatureError {
        fn from(e: secp256k1::Error) -> Self { Self::InvalidEncoding(e) }
    }

    /// A signature on a Bitcoin Signed Message.
    ///
    /// In order to use the `to_base64` and `from_base64` methods, as well as the
    /// `fmt::Display` and `str::FromStr` implementations, the `base64` feature
    /// must be enabled.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct MessageSignature {
        /// The inner recoverable signature.
        pub signature: RecoverableSignature,
        /// Whether or not this signature was created with a compressed key.
        pub compressed: bool,
    }

    impl MessageSignature {
        /// Constructs a new [MessageSignature].
        pub fn new(signature: RecoverableSignature, compressed: bool) -> Self {
            Self { signature, compressed }
        }

        /// Serializes to bytes.
        pub fn serialize(&self) -> [u8; 65] {
            let (recid, raw) = self.signature.serialize_compact();
            let mut serialized = [0u8; 65];
            serialized[0] = i32::from(recid) as u8 + if self.compressed { 31 } else { 27 };
            serialized[1..].copy_from_slice(&raw[..]);
            serialized
        }

        /// Constructs a new `MessageSignature` from a fixed-length array.
        pub fn from_byte_array(bytes: &[u8; 65]) -> Result<Self, secp256k1::Error> {
            // We just check this here so we can safely subtract further.
            if bytes[0] < 27 {
                return Err(secp256k1::Error::InvalidRecoveryId);
            };
            let recid = RecoveryId::try_from(((bytes[0] - 27) & 0x03) as i32)?;
            Ok(Self {
                signature: RecoverableSignature::from_compact(&bytes[1..], recid)?,
                compressed: ((bytes[0] - 27) & 0x04) != 0,
            })
        }

        /// Constructs a new `MessageSignature` from a byte slice.
        #[deprecated(since = "TBD", note = "use `from_byte_array` instead")]
        pub fn from_slice(bytes: &[u8]) -> Result<Self, MessageSignatureError> {
            let byte_array: [u8; 65] =
                bytes.try_into().map_err(|_| MessageSignatureError::InvalidLength)?;
            Self::from_byte_array(&byte_array).map_err(MessageSignatureError::from)
        }

        /// Attempt to recover a public key from the signature and the signed message.
        ///
        /// To get the message hash from a message, use [super::signed_msg_hash].
        pub fn recover_pubkey<C: secp256k1::Verification>(
            &self,
            secp_ctx: &secp256k1::Secp256k1<C>,
            msg_hash: sha256d::Hash,
        ) -> Result<PublicKey, MessageSignatureError> {
            let msg = secp256k1::Message::from_digest(msg_hash.to_byte_array());
            let pubkey = secp_ctx.recover_ecdsa(&msg, &self.signature)?;
            Ok(PublicKey { inner: pubkey, compressed: self.compressed })
        }

        /// Verifies that the signature signs the message and was signed by the given address.
        ///
        /// To get the message hash from a message, use [super::signed_msg_hash].
        pub fn is_signed_by_address<C: secp256k1::Verification>(
            &self,
            secp_ctx: &secp256k1::Secp256k1<C>,
            address: &Address,
            msg_hash: sha256d::Hash,
        ) -> Result<bool, MessageSignatureError> {
            match address.address_type() {
                Some(AddressType::P2pkh) => {
                    let pubkey = self.recover_pubkey(secp_ctx, msg_hash)?;
                    Ok(address.pubkey_hash() == Some(pubkey.pubkey_hash()))
                }
                Some(address_type) =>
                    Err(MessageSignatureError::UnsupportedAddressType(address_type)),
                None => Ok(false),
            }
        }
    }

    #[cfg(feature = "base64")]
    mod base64_impls {
        use base64::prelude::{Engine as _, BASE64_STANDARD};

        use super::*;
        use crate::prelude::String;

        impl MessageSignature {
            /// Converts a signature from base64 encoding.
            pub fn from_base64(s: &str) -> Result<Self, MessageSignatureError> {
                if s.len() != 88 {
                    return Err(MessageSignatureError::InvalidLength);
                }
                let mut byte_array = [0; 65];
                BASE64_STANDARD
                    .decode_slice_unchecked(s, &mut byte_array)
                    .map_err(|_| MessageSignatureError::InvalidBase64)?;
                Self::from_byte_array(&byte_array).map_err(MessageSignatureError::from)
            }

            /// Converts to base64 encoding.
            pub fn to_base64(self) -> String { BASE64_STANDARD.encode(self.serialize()) }
        }

        impl fmt::Display for MessageSignature {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let bytes = self.serialize();
                // This avoids the allocation of a String.
                write!(f, "{}", base64::display::Base64Display::new(&bytes, &BASE64_STANDARD))
            }
        }

        impl core::str::FromStr for MessageSignature {
            type Err = MessageSignatureError;
            fn from_str(s: &str) -> Result<Self, MessageSignatureError> { Self::from_base64(s) }
        }
    }
}

/// Hash message for signature using Bitcoin's message signing format.
pub fn signed_msg_hash(msg: impl AsRef<[u8]>) -> sha256d::Hash {
    let msg_bytes = msg.as_ref();
    let mut engine = sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    engine.emit_compact_size(msg_bytes.len()).expect("engines don't error");
    engine.input(msg_bytes);
    sha256d::Hash::from_engine(engine)
}

/// Sign message using Bitcoin's message signing format.
#[cfg(feature = "secp-recovery")]
pub fn sign<C: secp256k1::Signing>(
    secp_ctx: &secp256k1::Secp256k1<C>,
    msg: impl AsRef<[u8]>,
    privkey: SecretKey,
) -> MessageSignature {
    let msg_hash = signed_msg_hash(msg);
    let msg_to_sign = secp256k1::Message::from_digest(msg_hash.to_byte_array());
    let secp_sig = secp_ctx.sign_ecdsa_recoverable(&msg_to_sign, &privkey);
    MessageSignature { signature: secp_sig, compressed: true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_msg_hash() {
        let hash = signed_msg_hash("test");
        assert_eq!(
            hash.to_string(),
            "a6f87fe6d58a032c320ff8d1541656f0282c2c7bfcc69d61af4c8e8ed528e49c"
        );
    }

    #[test]
    #[cfg(all(feature = "secp-recovery", feature = "base64", feature = "rand-std"))]
    fn message_signature() {
        use secp256k1;

        use crate::{Address, AddressType, Network, NetworkKind};

        let secp = secp256k1::Secp256k1::new();
        let message = "rust-bitcoin MessageSignature test";
        let msg_hash = super::signed_msg_hash(message);
        let msg = secp256k1::Message::from_digest(msg_hash.to_byte_array());
        let privkey = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
        let secp_sig = secp.sign_ecdsa_recoverable(&msg, &privkey);
        let signature = super::MessageSignature { signature: secp_sig, compressed: true };

        assert_eq!(signature.to_string(), super::sign(&secp, message, privkey).to_string());
        assert_eq!(signature.to_base64(), signature.to_string());
        let signature2 = &signature.to_string().parse::<super::MessageSignature>().unwrap();
        let pubkey = signature2
            .recover_pubkey(&secp, msg_hash)
            .unwrap()
            .try_into()
            .expect("compressed was set to true");

        let p2pkh = Address::p2pkh(pubkey, NetworkKind::Main);
        assert_eq!(signature2.is_signed_by_address(&secp, &p2pkh, msg_hash), Ok(true));
        let p2wpkh = Address::p2wpkh(pubkey, Network::Bitcoin);
        assert_eq!(
            signature2.is_signed_by_address(&secp, &p2wpkh, msg_hash),
            Err(MessageSignatureError::UnsupportedAddressType(AddressType::P2wpkh))
        );
        let p2shwpkh = Address::p2shwpkh(pubkey, NetworkKind::Main);
        assert_eq!(
            signature2.is_signed_by_address(&secp, &p2shwpkh, msg_hash),
            Err(MessageSignatureError::UnsupportedAddressType(AddressType::P2sh))
        );
        let p2pkh = Address::p2pkh(pubkey, Network::Bitcoin);
        assert_eq!(signature2.is_signed_by_address(&secp, &p2pkh, msg_hash), Ok(true));

        assert_eq!(pubkey.0, secp256k1::PublicKey::from_secret_key(&secp, &privkey));
        let signature_base64 = signature.to_base64();
        let signature_round_trip =
            super::MessageSignature::from_base64(&signature_base64).expect("message signature");
        assert_eq!(signature, signature_round_trip);
    }

    #[test]
    #[cfg(all(feature = "secp-recovery", feature = "base64"))]
    fn incorrect_message_signature() {
        use base64::prelude::{Engine as _, BASE64_STANDARD};
        use secp256k1;

        use crate::crypto::key::PublicKey;
        use crate::{Address, NetworkKind};

        let secp = secp256k1::Secp256k1::new();
        let message = "a different message from what was signed";
        let msg_hash = super::signed_msg_hash(message);

        // Signature of msg = "rust-bitcoin MessageSignature test"
        // Signed with pk "UuOGDsfLPr4HIMKQX0ipjJeRaj1geCq3yPUF2COP5ME="
        let signature_base64 = "IAM2qX24tYx/bdBTIgVLhD8QEAjrPlJpmjB4nZHdRYGIBa4DmVulAcwjPnWe6Q5iEwXH6F0pUCJP/ZeHPWS1h1o=";
        let pubkey_base64 = "A1FTfMEntPpAty3qkEo0q2Dc1FEycI10a3jmwEFy+Qr6";
        let signature =
            super::MessageSignature::from_base64(signature_base64).expect("message signature");

        let pubkey =
            PublicKey::from_slice(&BASE64_STANDARD.decode(pubkey_base64).expect("base64 string"))
                .expect("pubkey slice");

        let p2pkh = Address::p2pkh(pubkey, NetworkKind::Main);
        assert_eq!(signature.is_signed_by_address(&secp, &p2pkh, msg_hash), Ok(false));
    }
}
