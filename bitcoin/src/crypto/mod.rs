// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.

pub mod ecdsa;
pub mod key;
pub mod sighash;
// Contents re-exported in `bitcoin::taproot`.
pub(crate) mod taproot;

use hashes::{sha256t, HashEngine as _};
use taproot_primitives::{TapNodeHash, TapTweakHash, TapTweakTag};

use self::key::UntweakedPublicKey;

/// Extension functionality for the [`TapTweakHash`] type.
pub trait TapTweakHashExt: sealed::Sealed {
        /// Constructs a new BIP-0341 [`TapTweakHash`] from key and Merkle root. Produces `H_taptweak(P||R)` where
        /// `P` is the internal key and `R` is the Merkle root.
        fn from_key_and_merkle_root<K: Into<UntweakedPublicKey>>(
            internal_key: K,
            merkle_root: Option<TapNodeHash>,
        ) -> Self;
}

impl TapTweakHashExt for TapTweakHash {
    fn from_key_and_merkle_root<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let mut eng = sha256t::Hash::<TapTweakTag>::engine();
        // always hash the key
        eng.input(&internal_key.serialize());
        if let Some(h) = merkle_root {
            eng.input(h.as_ref());
        } else {
            // nothing to hash
        }
        let inner = sha256t::Hash::<TapTweakTag>::from_engine(eng);
        Self::from_byte_array(inner.to_byte_array())
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::TapTweakHash {}
}
