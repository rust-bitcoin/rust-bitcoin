// SPDX-License-Identifier: CC0-1.0

//! # Bitcoin Addresses
//!
//! Bitcoin addresses do not appear on chain; rather, they are conventions used by Bitcoin (wallet)
//! software to communicate where coins should be sent and are based on the output type e.g., P2WPKH.
//!
//! This crate can be used in a no-std environment but requires an allocator.
//!
//! ref: <https://sprovoost.nl/2022/11/10/what-is-a-bitcoin-address/>

#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
pub mod witness_program;

#[cfg(feature = "alloc")]
use crypto::key::{LegacyPublicKey, UntweakedPublicKey, TweakedPublicKey, PubkeyHash};
#[cfg(feature = "alloc")]
use primitives::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
#[cfg(feature = "alloc")]
use primitives::script::{Builder, PushBytes, ScriptBuf, ScriptPubKeyBuf};
#[cfg(feature = "alloc")]
use primitives::witness_version::WitnessVersion;
#[cfg(feature = "alloc")]
use taproot_primitives::{TapNodeHash, TapTweak as _};

#[cfg(feature = "alloc")]
use witness_program::WitnessProgram;

/// Extension functionality for the [`ScriptPubKeyBuf`] type.
#[cfg(feature = "alloc")]
pub trait ScriptPubKeyBufExt: sealed::Sealed {
    /// Generates P2PK-type of scriptPubkey.
    fn new_p2pk(pubkey: LegacyPublicKey) -> Self;

    /// Generates P2PKH-type of scriptPubkey.
    fn new_p2pkh(pubkey_hash: PubkeyHash) -> Self;

    /// Generates P2TR for script spending path using an internal public key and some optional
    /// script tree Merkle root.
    fn new_p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self;

    /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
    fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self;

    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
    fn new_witness_program(witness_program: &WitnessProgram) -> Self;
}

#[cfg(feature = "alloc")]
impl ScriptPubKeyBufExt for ScriptPubKeyBuf {
    /// Generates P2PK-type of scriptPubkey.
    fn new_p2pk(pubkey: LegacyPublicKey) -> Self {
        Builder::new()
            .push_slice(pubkey.serialize())
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn new_p2pkh(pubkey_hash: PubkeyHash) -> Self {
        Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(pubkey_hash)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// Generates P2TR for script spending path using an internal public key and some optional
    /// script tree Merkle root.
    fn new_p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let output_key = internal_key.tap_tweak(merkle_root);
        // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
        new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
    }

    /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
    fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
        new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
    }

    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
    fn new_witness_program(witness_program: &WitnessProgram) -> Self {
        Builder::new()
            .push_opcode(witness_program.version().into())
            .push_slice(witness_program.program())
            .into_script()
    }
}

#[cfg(feature = "alloc")]
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ScriptPubKeyBuf {}
}

/// Generates P2WSH-type of scriptPubkey with a given [`WitnessVersion`] and the program bytes.
/// Does not do any checks on version or program length.
///
/// Convenience method used by `new_p2a`, `new_p2wpkh`, `new_p2wsh`, `new_p2tr`, and `new_p2tr_tweaked`.
#[cfg(feature = "alloc")]
fn new_witness_program_unchecked<T: AsRef<PushBytes>, Tg>(
    version: WitnessVersion,
    program: T,
) -> ScriptBuf<Tg> {
    let program = program.as_ref();
    debug_assert!(program.len() >= 2 && program.len() <= 40);
    // In SegWit v0, the program must be either 20 bytes (P2WPKH) or 32 bytes (P2WSH) long.
    debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
    Builder::new().push_opcode(version.into()).push_slice(program).into_script()
}
