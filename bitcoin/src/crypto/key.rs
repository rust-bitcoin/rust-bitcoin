// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use core::borrow::Borrow;
use core::ops::Deref;

use crypto::sighash::TapTweakHashExt as _;

use crate::internal_macros::define_extension_trait;
use crate::script::{self, PushBytes, WitnessScriptBuf};
#[cfg(feature = "secp-recovery")]
use crate::sign_message::MessageSignature;
use crate::taproot::{TapNodeHash, TapTweakHash};

#[rustfmt::skip]                // Keep public re-exports separate.
pub use secp256k1::{constants, Parity, Verification};
#[doc(no_inline)]
pub use crypto::key::{
    FromSliceError, FromWifError, InvalidAddressVersionError, InvalidBase58PayloadLengthError,
    InvalidWifCompressionFlagError, ParseFullPublicKeyError, ParseXOnlyPublicKeyError,
    TweakXOnlyPublicKeyError, UncompressedPublicKeyError,
};
#[doc(inline)]
pub use crypto::key::{
    FullPublicKey, Keypair, LegacyPublicKey, PrivateKey, PubkeyHash, SerializedLegacyPublicKey,
    SerializedXOnlyPublicKey, TweakedKeypair, TweakedPublicKey, UntweakedKeypair,
    UntweakedPublicKey, WPubkeyHash, WifKey, XOnlyPublicKey,
};

impl AsRef<PushBytes> for SerializedLegacyPublicKey {
    fn as_ref(&self) -> &PushBytes { self.borrow() }
}

impl Borrow<PushBytes> for SerializedLegacyPublicKey {
    fn borrow(&self) -> &PushBytes { <&PushBytes>::try_from(self.deref()).expect("65 <= u32::MAX") }
}

#[deprecated(since = "TBD", note = "use `LegacyPublicKey` instead")]
#[doc(hidden)]
pub type PublicKey = LegacyPublicKey;

#[deprecated(since = "TBD", note = "use `FullPublicKey` instead")]
#[doc(hidden)]
pub type CompressedPublicKey = FullPublicKey;

define_extension_trait! {
    /// Extension functionality for the [`FullPublicKey`] type.
    pub trait FullPublicKeyExt impl for FullPublicKey {
        /// Returns the script code used to spend a P2WPKH input.
        ///
        /// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
        /// should not be used as one. It is a special template defined in BIP 143 which is used
        /// in place of a witness script for purposes of sighash computation.
        fn p2wpkh_script_code(&self) -> WitnessScriptBuf {
            script::p2wpkh_script_code(self.wpubkey_hash())
        }
    }
}

define_extension_trait! {
    /// Extension functionality for the [`LegacyPublicKey`] type.
    pub trait LegacyPublicKeyExt impl for LegacyPublicKey {
        /// Returns the script code used to spend a P2WPKH input.
        ///
        /// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
        /// should not be used as one. It is a special template defined in BIP 143 which is used
        /// in place of a witness script for purposes of sighash computation.
        ///
        /// # Errors
        ///
        /// Errors if this key is not compressed.
        fn p2wpkh_script_code(&self) -> Result<WitnessScriptBuf, UncompressedPublicKeyError> {
            let key = FullPublicKey::try_from(*self)?;
            Ok(key.p2wpkh_script_code())
        }
    }
}

#[cfg(feature = "secp-recovery")]
define_extension_trait! {
    /// Extension functionality for the [`PrivateKey`] type.
    pub trait PrivateKeyExt impl for PrivateKey {
        /// ECDSA signs a [`Message`] with this private key.
        ///
        /// This produces an ECDSA signature with a recovery ID for pubkey recovery.
        /// See [`RecoverableSignature::sign_ecdsa_recoverable`] for details.
        ///
        /// [`Message`]: secp256k1::Message
        /// [`RecoverableSignature::sign_ecdsa_recoverable`]: secp256k1::ecdsa::RecoverableSignature::sign_ecdsa_recoverable
        #[inline]
        fn raw_ecdsa_sign_recoverable(
            &self,
            msg: impl Into<secp256k1::Message>,
        ) -> MessageSignature {
            MessageSignature::new(
                secp256k1::ecdsa::RecoverableSignature::sign_ecdsa_recoverable(msg, self.as_inner()),
                self.compressed(),
            )
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::FullPublicKey {}
    impl Sealed for super::LegacyPublicKey {}
    impl Sealed for super::PrivateKey {}
}

/// A trait for tweaking BIP-0340 key types (x-only public keys and key pairs).
pub trait TapTweak {
    /// Tweaked key type with optional auxiliary information.
    type TweakedAux;
    /// Tweaked key type.
    type TweakedKey;

    /// Tweaks an untweaked key with corresponding public key value and optional script tree Merkle
    /// root. For the [`Keypair`] type this also tweaks the private key in the pair.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    ///
    /// The tweaked key, with the required parity.
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> Self::TweakedAux;

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`].
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = TweakedPublicKey;
    type TweakedKey = TweakedPublicKey;

    /// Tweaks an untweaked public key with corresponding public key value and optional script tree
    /// Merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    ///
    /// The tweaked key and its parity.
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> TweakedPublicKey {
        let tweak = TapTweakHash::from_key_and_merkle_root(self, merkle_root).to_scalar();
        let output_key = self.add_tweak(&tweak).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(&output_key, tweak));
        TweakedPublicKey::dangerous_assume_tweaked(output_key)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey::dangerous_assume_tweaked(self)
    }
}

impl TapTweak for UntweakedKeypair {
    type TweakedAux = TweakedKeypair;
    type TweakedKey = TweakedKeypair;

    /// Applies a Taproot tweak to both keys within the keypair.
    ///
    /// If `merkle_root` is provided, produces a Taproot key that can be spent by any
    /// of the script paths committed to by the root. If it is not provided, produces
    /// a Taproot key which can [provably only be spent via
    /// keyspend](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-23).
    ///
    /// # Returns
    ///
    /// The tweaked keypair.
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> TweakedKeypair {
        let pubkey = XOnlyPublicKey::from_keypair(&self);
        let tweak = TapTweakHash::from_key_and_merkle_root(pubkey, merkle_root).to_scalar();
        let tweaked = self.as_inner().add_xonly_tweak(&tweak).expect("Tap tweak failed");
        TweakedKeypair::dangerous_assume_tweaked(Self::from(tweaked))
    }

    fn dangerous_assume_tweaked(self) -> TweakedKeypair {
        TweakedKeypair::dangerous_assume_tweaked(self)
    }
}

crate::internal_macros::impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::address::Address;
    use crate::network::NetworkKind;

    #[test]
    fn key_derivation() {
        // mainnet compressed WIF with invalid compression flag.
        let sk = WifKey::from_wif("L2x4uC2YgfFWZm9tF4pjDnVR6nJkheizFhEr2KvDNnTEmEqVzPJY");
        assert!(matches!(sk, Err(FromWifError::InvalidWifCompressionFlag(_))));

        // testnet compressed
        let sk = WifKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network_kind, NetworkKind::Test);
        assert!(sk.private_key.compressed());
        assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

        let pk = Address::p2pkh(sk.private_key.to_public_key(), sk.network_kind);
        assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // test string conversion
        assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
        let sk_str =
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy".parse::<WifKey>().unwrap();
        assert_eq!(&sk.to_wif(), &sk_str.to_wif());

        // mainnet uncompressed
        let sk = WifKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(sk.network_kind, NetworkKind::Main);
        assert!(!sk.private_key.compressed());
        assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

        let mut pk = sk.private_key.to_public_key();
        assert!(!pk.compressed());
        assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
        assert_eq!(pk, "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133"
        .parse::<LegacyPublicKey>().unwrap());
        let addr = Address::p2pkh(pk, sk.network_kind);
        assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
        pk = LegacyPublicKey::from_secp(pk.to_inner());
        assert_eq!(
            &pk.to_string(),
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        );
        assert_eq!(
            pk,
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
                .parse::<LegacyPublicKey>()
                .unwrap()
        );
    }
}
