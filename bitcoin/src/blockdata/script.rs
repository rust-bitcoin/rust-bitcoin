// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.
//!
//! *[See also the `Script` type](Script).*
//!
//! This module provides the structures and functions needed to support scripts.
//!
//! <details>
//! <summary>What is Bitcoin script</summary>
//!
//! Scripts define Bitcoin's digital signature scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid iff
//! the script leaves `TRUE` on the stack after being evaluated. Bitcoin's
//! script is a stack-based assembly language similar in spirit to [Forth].
//!
//! Script is represented as a sequence of bytes on the wire, each byte representing an operation,
//! or data to be pushed on the stack.
//!
//! See [Bitcoin Wiki: Script][wiki-script] for more information.
//!
//! [Forth]: https://en.wikipedia.org/wiki/Forth_(programming_language)
//!
//! [wiki-script]: https://en.bitcoin.it/wiki/Script
//! </details>
//!
//! In this library we chose to keep the byte representation in memory and decode opcodes only when
//! processing the script. This is similar to Rust choosing to represent strings as UTF-8-encoded
//! bytes rather than slice of `char`s. In both cases the individual items can have different sizes
//! and forcing them to be larger would waste memory and, in case of Bitcoin script, even some
//! performance (forcing allocations).
//!
//! ## `Script` vs `ScriptBuf` vs `Builder`
//!
//! These are the most important types in this module and they are quite similar, so it may seem
//! confusing what the differences are. `Script` is an unsized type much like `str` or `Path` are
//! and `ScriptBuf` is an owned counterpart to `Script` just like `String` is an owned counterpart
//! to `str`.
//!
//! However it is common to construct an owned script and then pass it around. For this case a
//! builder API is more convenient. To support this we provide `Builder` type which is very similar
//! to `ScriptBuf` but its methods take `self` instead of `&mut self` and return `Self`. It also
//! contains a cache that may make some modifications faster. This cache is usually not needed
//! outside of creating the script.
//!
//! At the time of writing there's only one operation using the cache - `push_verify`, so the cache
//! is minimal but we may extend it in the future if needed.

#[cfg(test)]
mod tests;

use io::{BufRead, Write};
use primitives::opcodes::all::*;

use crate::consensus::{encode, Decodable, Encodable};
use crate::internal_macros::define_extension_trait;
use crate::key::WPubkeyHash;
use crate::policy::DUST_RELAY_TX_FEE;
use crate::prelude::sink;
use crate::taproot::{LeafVersion, TapLeafHash};
use crate::FeeRate;

/// Re-export everything from the [`primitives::script`] module.
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::script::*;

define_extension_trait! {
    /// Extension functionality for the [`Script`] type.
    pub trait ScriptExt impl for Script {
        /// Computes leaf hash of tapscript.
        fn tapscript_leaf_hash(&self) -> TapLeafHash {
            TapLeafHash::from_script(self, LeafVersion::TapScript)
        }

        /// Returns the minimum value an output with this script should have in order to be
        /// broadcastable on today's Bitcoin network.
        ///
        /// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
        /// This function uses the default value of 0.00003 BTC/kB (3 sat/vByte).
        ///
        /// To use a custom value, use [`minimal_non_dust_custom`].
        ///
        /// [`minimal_non_dust_custom`]: Script::minimal_non_dust_custom
        fn minimal_non_dust(&self) -> crate::Amount {
            minimal_non_dust_inner(self, DUST_RELAY_TX_FEE.into())
        }

        /// Returns the minimum value an output with this script should have in order to be
        /// broadcastable on today's Bitcoin network.
        ///
        /// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
        /// This function lets you set the fee rate used in dust calculation.
        ///
        /// The current default value in Bitcoin Core (as of v26) is 3 sat/vByte.
        ///
        /// To use the default Bitcoin Core value, use [`minimal_non_dust`].
        ///
        /// [`minimal_non_dust`]: Script::minimal_non_dust
        fn minimal_non_dust_custom(&self, dust_relay_fee: FeeRate) -> crate::Amount {
            minimal_non_dust_inner(self, dust_relay_fee.to_sat_per_kwu() * 4)
        }
    }
}

pub(crate) fn minimal_non_dust_inner(script: &Script, dust_relay_fee: u64) -> crate::Amount {
    // This must never be lower than Bitcoin Core's GetDustThreshold() (as of v0.21) as it may
    // otherwise allow users to create transactions which likely can never be broadcast/confirmed.
    let sats = dust_relay_fee
        .checked_mul(if script.is_op_return() {
            0
        } else if script.is_witness_program() {
            32 + 4 + 1 + (107 / 4) + 4 + // The spend cost copied from Core
                8 + // The serialized size of the TxOut's amount field
                script.consensus_encode(&mut sink()).expect("sinks don't error") as u64 // The serialized size of this script_pubkey
        } else {
            32 + 4 + 1 + 107 + 4 + // The spend cost copied from Core
                8 + // The serialized size of the TxOut's amount field
                script.consensus_encode(&mut sink()).expect("sinks don't error") as u64 // The serialized size of this script_pubkey
        })
        .expect("dust_relay_fee or script length should not be absurdly large")
        / 1000; // divide by 1000 like in Core to get value as it cancels out DEFAULT_MIN_RELAY_TX_FEE
                // Note: We ensure the division happens at the end, since Core performs the division at the end.
                //       This will make sure none of the implicit floor operations mess with the value.

    crate::Amount::from_sat(sats)
}

/// Iterates the script to find the last pushdata.
///
/// Returns `None` if the instruction is an opcode or if the script is empty.
pub(crate) fn last_pushdata(script: &Script) -> Option<&PushBytes> {
    match script.instructions().last() {
        // Handles op codes up to (but excluding) OP_PUSHNUM_NEG.
        Some(Ok(Instruction::PushBytes(bytes))) => Some(bytes),
        // OP_16 (0x60) and lower are considered "pushes" by Bitcoin Core (excl. OP_RESERVED).
        // However we are only interested in the pushdata so we can ignore them.
        _ => None,
    }
}

/// Creates the script code used for spending a P2WPKH output.
///
/// The `scriptCode` is described in [BIP143].
///
/// [BIP143]: <https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki>
pub fn p2wpkh_script_code(wpkh: WPubkeyHash) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(wpkh)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Constructor functions for various witness programs.
pub mod witness_program {
    use secp256k1::{Secp256k1, Verification};

    use crate::key::{CompressedPublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};
    use crate::TapNodeHash;

    /// Re-export everything from the [`primitives::script::witness_program`] module.
    #[rustfmt::skip]                // Keep public re-exports separate.
    #[doc(inline)]
    pub use primitives::script::witness_program::*;

    /// Creates a [`WitnessProgram`] from `pk` for a P2WPKH output.
    pub fn p2wpkh(pk: CompressedPublicKey) -> WitnessProgram {
        let hash = pk.wpubkey_hash();
        WitnessProgram::new_p2wpkh(hash.to_byte_array())
    }

    /// Creates a pay to Taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> WitnessProgram {
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        let pubkey = output_key.to_inner().serialize();
        WitnessProgram::new_p2tr(pubkey)
    }

    /// Creates a pay to Taproot address from a pre-tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey) -> WitnessProgram {
        let pubkey = output_key.to_inner().serialize();
        WitnessProgram::new_p2tr(pubkey)
    }
}

impl Encodable for Script {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        crate::consensus::encode::consensus_encode_with_size(self.as_bytes(), w)
    }
}

impl Encodable for ScriptBuf {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_script().consensus_encode(w)
    }
}

impl Decodable for ScriptBuf {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        Ok(ScriptBuf::from_bytes(Decodable::consensus_decode_from_finite_reader(r)?))
    }
}
