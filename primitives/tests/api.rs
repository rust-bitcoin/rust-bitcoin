// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `primitives`.
//!
//! The point of these tests are to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
// These imports test "typical" usage by user code.
use bitcoin_primitives::locktime::{absolute, relative}; // Typical usage is `absolute::Height`.
use bitcoin_primitives::{
    amount, block, fee_rate, locktime, merkle_tree, opcodes, pow,
    script, sequence, taproot, transaction, weight, witness, Amount,
    Block, BlockHash, BlockHeader, BlockHeight, BlockInterval,
    CompactTarget, FeeRate, Sequence, SignedAmount, TapBranchTag,
    TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag,
    Transaction, TxIn, TxMerkleNode, TxOut, Txid, Weight, Witness,
    WitnessCommitment, WitnessMerkleNode, Wtxid,
    BlockChecked, BlockUnchecked
};

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: amount::Denomination,
}

impl Enums {
    fn new() -> Self {
        Self { a: amount::Denomination::Bitcoin }
    }
}

/// A struct that includes all public non-error structs.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Structs {
    a: Amount,
    b: Block,
    c: BlockHash,
    d: BlockHeader,
    e: BlockHeight,
    f: BlockInterval,
    g: CompactTarget,
    h: FeeRate,
    i: absolute::Height,
    j: absolute::Time,
    k: relative::Height,
    l: relative::Time,
    m: relative::Time,
    n: Sequence,
    o: SignedAmount,
    p: TapBranchTag,
    q: TapLeafHash,
    r: TapLeafTag,
    s: TapNodeHash,
    t: TapTweakHash,
    u: TapTweakTag,
    v: Transaction,
    w: TxIn,
    x: TxMerkleNode,
    y: TxOut,
    z: Txid,
    _a: Weight,
    _b: Witness,
    _c: WitnessCommitment

}

#[test]
fn api_can_use_modules_from_crate_root() {
  use bitcoin_primitives::{
    absolute, amount, block, fee_rate, locktime,
    merkle_tree, opcodes, pow, relative, script,
    sequence, taproot, transaction, weight, witness
  };
}

#[test]
fn api_can_use_types_from_crate_root() {
  use bitcoin_primitives::{
    Amount, Block, BlockHash, BlockHeader, BlockHeight, BlockInterval,
    CompactTarget, FeeRate, Sequence, SignedAmount, TapBranchTag,
    TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag,
    Transaction, TxIn, TxMerkleNode, TxOut, Txid, Weight, Witness,
    WitnessCommitment, WitnessMerkleNode, Wtxid,
    BlockChecked, BlockUnchecked
  };
}

#[test]
fn api_can_use_all_types_from_module_absolute() {
  use bitcoin_primitives::absolute::{
    ConversionError, Height, ParseHeightError, ParseTimeError, Time,
    LockTime
  };
}

#[test]
fn api_can_use_all_types_from_module_amount() {
  use bitcoin_primitives::amount::{
    Amount, Display, InputTooLargeError, InvalidCharacterError, MissingDenominationError,MissingDigitsError,
    OutOfRangeError, ParseAmountError, ParseError, PossiblyConfusingDenominationError, SignedAmount,
    TooPreciseError, UnknownDenominationError, Denomination, ParseDenominationError
  };
}

#[rustfmt::skip]
#[test]
fn api_can_use_all_types_from_module_block() {
  {
    // New types added in `primitives`.
    use bitcoin_primitives::block::{
      Block, BlockHash, Header, Version, WitnessCommitment,
      Checked, Unchecked
    };
  }
  {
    // Re-exports from `units`
    use units::block::{BlockHeight, BlockInterval, TooBigForRelativeBlockHeightError};
  }
}

#[test]
fn api_can_use_all_types_from_module_fee_rate() {
  use bitcoin_primitives::fee_rate::FeeRate;
}

#[test]
fn api_can_use_all_types_from_module_locktime_absolute() {
  use bitcoin_primitives::locktime::absolute::{
    ConversionError, Height, ParseHeightError, ParseTimeError, Time, LockTime
  };
}

#[test]
fn api_can_use_all_types_from_module_locktime_relative() {
  use bitcoin_primitives::locktime::relative::{
    DisabledLockTimeError, Height, IncompatibleHeightError, IncompatibleTimeError,
    Time, TimeOverflowError, LockTime
  };
}

#[test]
fn api_can_use_all_types_from_module_merkle_tree() {
  use bitcoin_primitives::merkle_tree::{TxMerkleNode, WitnessMerkleNode};
}

#[test]
fn api_can_use_all_types_from_module_opcodes() {
  use bitcoin_primitives::opcodes::{
    Opcode, Class, ClassifyContext
  };
}

#[test]
fn api_can_use_all_types_from_module_pow() {
  use bitcoin_primitives::pow::CompactTarget;
}

#[test]
fn api_can_use_all_types_from_module_relative() {
  use bitcoin_primitives::relative::{
    DisabledLockTimeError, Height, IncompatibleHeightError, IncompatibleTimeError,
    Time, TimeOverflowError, LockTime
  };
}

#[test]
fn api_can_use_all_types_from_module_script() {
  use bitcoin_primitives::script::{
    RedeemScriptSizeError, Script, ScriptBuf, ScriptHash, WScriptHash, WitnessScriptSizeError
  };
}

#[test]
fn api_can_use_all_types_from_module_sequence() {
  use bitcoin_primitives::sequence::Sequence;
}

#[test]
fn api_can_use_all_types_from_module_taproot() {
  use bitcoin_primitives::taproot::{
    TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash,
    TapTweakHash, TapTweakTag
  };
}

#[test]
fn api_can_use_all_types_from_module_transaction() {
  use bitcoin_primitives::transaction::{
    OutPoint, Transaction, TxIn, TxOut, Txid, Version, Wtxid, ParseOutPointError
  };
}

#[test]
fn api_can_use_all_types_from_module_weight() {
  use bitcoin_primitives::weight::Weight;
}

#[test]
fn api_can_use_all_types_from_module_witness() {
  use bitcoin_primitives::witness::{Iter, Witness};
}