// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use crate::internal_macros::define_extension_trait;
use crate::script::{self, WitnessScriptBuf};

#[rustfmt::skip]                // Keep public re-exports separate.
pub use secp256k1::{constants, Parity};
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
#[doc(inline)]
pub use taproot_primitives::TapTweak;

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

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::FullPublicKey {}
    impl Sealed for super::LegacyPublicKey {}
}

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

        let mut pk = sk.private_key.to_legacy_public_key();
        assert!(!pk.compressed());
        assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
        assert_eq!(pk, "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133"
        .parse::<LegacyPublicKey>().unwrap());
        let addr = Address::p2pkh(pk, sk.network_kind);
        assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
        pk = pk.with_compressedness(true);
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
