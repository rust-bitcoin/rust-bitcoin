// SPDX-License-Identifier: CC0-1.0

//! Stable compatibility layer.
//!
//! This module re-exports types from stable crates (e.g. `bitcoin-units-1.0.0`). The aim is to ease
//! the upgrade path from `bitcoin 0.32` to subsequent `bitcoin` versions as we release them.
//!
//! Everything is re-exported at the same path as it appears in the stable `bitcoin-primitives`
//! crate, which itself re-exports the `bitcoin-units` types.
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
//! Stable scripts are tagged with the role they play, pre-1.0 scripts are not. The tag is selected
//! when converting to the stable type and discarded when converting back.
//!
//! ```
//! use bitcoin::{compat, ScriptBuf};
//!
//! let script = ScriptBuf::from_bytes(vec![0x51]);
//! let stable: compat::ScriptPubKeyBuf = script.clone().to_stable();
//!
//! let unstable = ScriptBuf::from_stable(stable);
//! assert_eq!(unstable, script);
//! ```

#[doc(inline)]
pub use bitcoin_primitives_stable::{
    block, merkle_tree, opcodes, script, transaction, witness, witness_version,
};
#[doc(inline)]
pub use bitcoin_units_stable::{
    amount, fee_rate, locktime, parse_int, pow, result, sequence, time, weight,
};
#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{
        Block, BlockHash, BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval,
        Checked as BlockChecked, Header as BlockHeader, Unchecked as BlockUnchecked,
        Validation as BlockValidation, Version as BlockVersion, WitnessCommitment,
    },
    fee_rate::FeeRate,
    locktime::{absolute, relative},
    pow::{CompactTarget, Target, Work},
    result::NumOpResult,
    script::{
        RedeemScript, RedeemScriptBuf, ScriptCode, ScriptPubKey, ScriptPubKeyBuf, ScriptSig,
        ScriptSigBuf, SignetBlockScript, SignetBlockScriptBuf, TapScript, TapScriptBuf,
        WitnessScript, WitnessScriptBuf,
    },
    sequence::Sequence,
    time::BlockTime,
    transaction::{OutPoint, Transaction, TxIn, TxOut, Txid, Version as TransactionVersion, Wtxid},
    weight::Weight,
    witness::Witness,
};
