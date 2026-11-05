// SPDX-License-Identifier: CC0-1.0

//! Stable compatibility layer.
//!
//! This module re-exports types from the units and primitives crates. The aim is to ease
//! the upgrade path from `bitcoin 0.32` to subsequent `bitcoin` versions as we release them.
//!
//! With this module, coupled with the `to_stable`/`from_stable` functions, downstream projects can
//! update to use stable crates at their leisure without the whole ecosystem having to upgrade at
//! once. The intention is to provide stable types for the most common `rust-bitcoin` types used by
//! downstream libraries.
//!
//! # Examples
//!
//! ```
//! use bitcoin::Sequence;
//!
//! let seq = Sequence::default();
//! let stable = seq.to_stable();
//!
//! // Now call into some other library that uses stable types in its API.
//! // E.g., `other_lib::some_function(stable);`
//! let unstable = Sequence::from_stable(stable);
//! assert_eq!(unstable, seq);
//! ```
//!
//! Scripts in the primitives crate are tagged by their role. Specify the tag when converting
//! an untyped script; converting back discards the tag without changing the bytes.
//!
//! ```
//! use bitcoin::{compat, ScriptBuf};
//!
//! let script = ScriptBuf::from_bytes(vec![0x51]);
//! let stable: compat::ScriptPubKeyBuf = script.clone().to_stable();
//! assert_eq!(ScriptBuf::from_stable(stable), script);
//! ```

#[doc(inline)]
#[rustfmt::skip]
pub use bitcoin_primitives_stable::{
    block, merkle_tree, opcodes, script, transaction, witness, witness_version,
    Block, BlockChecked, BlockHash, BlockHeader, BlockUnchecked, BlockValidation, BlockVersion,
    OutPoint, RedeemScript, RedeemScriptBuf, ScriptCode, ScriptPubKey, ScriptPubKeyBuf,
    ScriptSig, ScriptSigBuf, SignetBlockScript, SignetBlockScriptBuf, TapScript, TapScriptBuf,
    Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness, WitnessCommitment, WitnessScript,
    WitnessScriptBuf, Wtxid,
};
#[doc(inline)]
pub use bitcoin_primitives_stable::{
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    opcodes::Opcode,
    transaction::Ntxid,
    witness_version::WitnessVersion,
};
#[doc(inline)]
pub use bitcoin_units_stable::{
    amount, fee_rate, locktime, parse_int, pow, result, sequence, time, weight,
};
#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    locktime::{absolute, relative},
    pow::{CompactTarget, Target, Work},
    result::NumOpResult,
    sequence::Sequence,
    time::BlockTime,
    weight::Weight
};
