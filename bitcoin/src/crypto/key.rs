// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use secp256k1::Parity;

use crate::internal_macros::define_extension_trait;
use crate::script::{self, WitnessScriptBuf};
use crate::taproot::{TapNodeHash, TapTweakHash};

#[doc(inline)]
pub use crypto::key::{
    CompressedPublicKey, Keypair, PrivateKey, PublicKey, PubkeyHash, SerializedXOnlyPublicKey, TweakedKeypair,
    UntweakedKeypair, UntweakedPublicKey, TweakedPublicKey, WPubkeyHash, XOnlyPublicKey,
};
#[doc(no_inline)]
pub use crypto::key::{
    FromSliceError, FromWifError, InvalidWifCompressionFlagError,
    ParseXOnlyPublicKeyError, UncompressedPublicKeyError,
};

define_extension_trait! {
    /// Extension functionality for the [`CompressedPublicKey`] type.
    pub trait CompressedPublicKeyExt impl for CompressedPublicKey {
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
    /// Extension functionality for the [`PublicKey`] type.
    pub trait PublicKeyExt impl for PublicKey {
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
            let key = CompressedPublicKey::try_from(*self)?;
            Ok(key.p2wpkh_script_code())
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::CompressedPublicKey {}
    impl Sealed for super::PublicKey {}
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
    /// The tweaked key and its parity.
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> Self::TweakedAux;

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`].
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = (TweakedPublicKey, Parity);
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
    fn tap_tweak(self, merkle_root: Option<TapNodeHash>) -> (TweakedPublicKey, Parity) {
        let tweak = TapTweakHash::from_key_and_merkle_root(self, merkle_root).to_scalar();
        let (output_key, parity) = self.add_tweak(&tweak).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(&output_key, parity, tweak));
        (TweakedPublicKey::dangerous_assume_tweaked(output_key), parity)
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
        let (pubkey, _parity) = XOnlyPublicKey::from_keypair(&self);
        let tweak = TapTweakHash::from_key_and_merkle_root(pubkey, merkle_root).to_scalar();
        let tweaked = self.to_inner().add_xonly_tweak(&tweak).expect("Tap tweak failed");
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
        let sk = PrivateKey::from_wif("L2x4uC2YgfFWZm9tF4pjDnVR6nJkheizFhEr2KvDNnTEmEqVzPJY");
        assert!(matches!(
            sk,
            Err(FromWifError::InvalidWifCompressionFlag(_))
        ));

        // testnet compressed
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network, NetworkKind::Test);
        assert!(sk.compressed);
        assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

        let pk = Address::p2pkh(sk.public_key(), sk.network);
        assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // test string conversion
        assert_eq!(&sk.to_string(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
        let sk_str =
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy".parse::<PrivateKey>().unwrap();
        assert_eq!(&sk.to_wif(), &sk_str.to_wif());

        // mainnet uncompressed
        let sk =
            PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(sk.network, NetworkKind::Main);
        assert!(!sk.compressed);
        assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

        let mut pk = sk.public_key();
        assert!(!pk.compressed);
        assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
        assert_eq!(pk, "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133"
        .parse::<PublicKey>().unwrap());
        let addr = Address::p2pkh(pk, sk.network);
        assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
        pk.compressed = true;
        assert_eq!(
            &pk.to_string(),
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        );
        assert_eq!(
            pk,
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
                .parse::<PublicKey>()
                .unwrap()
        );
    }
}
