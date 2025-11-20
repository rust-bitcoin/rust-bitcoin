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
use primitives::script::{WScriptHash, WitnessProgram, WitnessScript, WitnessScriptSizeError};
use taproot_primitives::{TapNodeHash, TapTweakHash, TapTweakTag};

use crate::crypto::key::{CompressedPublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};

// FIXME: We need to remove this.
#[rustfmt::skip]
use crate::script::WitnessScriptExt as _;

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

/// Extension functionality for the [`WitnessProgram`] type.
pub trait WitnessProgramExt: sealed::Sealed {
    /// Constructs a new [`WitnessProgram`] from `pk` for a P2WPKH output.
    fn p2wpkh(pk: CompressedPublicKey) -> Self;

    /// Constructs a new [`WitnessProgram`] from `script` for a P2WSH output.
    fn p2wsh(script: &WitnessScript) -> Result<WitnessProgram, WitnessScriptSizeError>;

    /// Constructs a new [`WitnessProgram`] from `script` for a P2WSH output.
    fn p2wsh_from_hash(hash: WScriptHash) -> WitnessProgram;

    /// Constructs a new [`WitnessProgram`] from an untweaked key for a P2TR output.
    ///
    /// This function applies BIP-0341 key-tweaking to the untweaked
    /// key using the merkle root, if it's present.
    fn p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> WitnessProgram;

    /// Constructs a new [`WitnessProgram`] from a tweaked key for a P2TR output.
    fn p2tr_tweaked(output_key: TweakedPublicKey) -> WitnessProgram;
}

impl WitnessProgramExt for WitnessProgram {
    fn p2wpkh(pk: CompressedPublicKey) -> Self {
        let hash = pk.wpubkey_hash();
        Self::new_p2wpkh(hash.to_byte_array())
    }

    fn p2wsh(script: &WitnessScript) -> Result<Self, WitnessScriptSizeError> {
        script.wscript_hash().map(Self::p2wsh_from_hash)
    }

    fn p2wsh_from_hash(hash: WScriptHash) -> Self { Self::new_p2wsh(hash.to_byte_array()) }

    fn p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let (output_key, _parity) = internal_key.tap_tweak(merkle_root);
        let pubkey = output_key.as_x_only_public_key().serialize();
        Self::new_p2tr(pubkey)
    }

    fn p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        let pubkey = output_key.as_x_only_public_key().serialize();
        Self::new_p2tr(pubkey)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::TapTweakHash {}
    impl Sealed for super::WitnessProgram {}
}
