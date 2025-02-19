// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `primitives`.
//!
//! The point of these tests are to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]
// No benefit in running this test without features enabled.
#![cfg(feature = "alloc")]
#![cfg(feature = "hex")]
#![cfg(feature = "arbitrary")]

use arbitrary::Arbitrary;
use bitcoin_primitives::block::{Checked, Unchecked};
use bitcoin_primitives::script::{self, ScriptHash, WScriptHash};
use bitcoin_primitives::{
    absolute, block, merkle_tree, pow, relative, transaction, witness, OutPoint, Script, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness, Wtxid,
};
use hashes::sha256t;

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: block::Checked, // Empty enums are not constructable.
    b: block::Unchecked,
    c: absolute::LockTime,
    d: relative::LockTime,
}

/// A struct that includes all public non-error structs.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Structs<'a> {
    a: block::Block<Checked>,
    b: block::Block<Unchecked>,
    c: block::Header,
    d: block::Version,
    e: block::BlockHash,
    f: block::WitnessCommitment,
    g: merkle_tree::TxMerkleNode,
    h: merkle_tree::WitnessMerkleNode,
    i: pow::CompactTarget,
    j: &'a Script,
    k: ScriptHash,
    l: WScriptHash,
    m: ScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Version,
    v: Witness,
    // w: witness::Iter<'a>,
}

static SCRIPT: ScriptBuf = ScriptBuf::new();
static BYTES: [u8; 32] = [0x00; 32];

/// Public structs that derive common traits.
// C-COMMON-TRAITS excluding `Debug, Default, Display, Ord, PartialOrd, Hash`.
#[derive(Clone, PartialEq, Eq)]
struct CommonTraits {
    a: block::Block<Checked>,
    b: block::Block<Unchecked>,
    c: block::Header,
    d: block::Version,
    e: block::BlockHash,
    f: block::WitnessCommitment,
    g: merkle_tree::TxMerkleNode,
    h: merkle_tree::WitnessMerkleNode,
    i: pow::CompactTarget,
    // j: &'a Script,
    k: ScriptHash,
    l: WScriptHash,
    m: ScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Version,
    v: Witness,
    // w: witness::Iter<'a>,
}

/// A struct that includes all types that implement `Clone`.
#[derive(Clone)] // C-COMMON-TRAITS: `Clone`
struct Clone<'a> {
    a: block::Block<Checked>,
    b: block::Block<Unchecked>,
    c: block::Header,
    d: block::Version,
    e: block::BlockHash,
    f: block::WitnessCommitment,
    g: merkle_tree::TxMerkleNode,
    h: merkle_tree::WitnessMerkleNode,
    i: pow::CompactTarget,
    // j: &'a Script,
    k: ScriptHash,
    l: WScriptHash,
    m: ScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Version,
    v: Witness,
    w: witness::Iter<'a>,
}

/// Public structs that derive common traits.
// C-COMMON-TRAITS excluding `Clone`, `Debug, `Default`, and `Display`
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Ord {
    // a: block::Block<Checked>,
    // b: block::Block<Unchecked>,
    c: block::Header,
    d: block::Version,
    e: block::BlockHash,
    f: block::WitnessCommitment,
    g: merkle_tree::TxMerkleNode,
    h: merkle_tree::WitnessMerkleNode,
    i: pow::CompactTarget,
    // j: &'a Script,  // Doesn't implement `Clone`.
    k: ScriptHash,
    l: WScriptHash,
    m: ScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Version,
    v: Witness,
    // w: witness::Iter<'a>,
}

/// A struct that includes all types that implement `Default`.
#[derive(Default, Debug, PartialEq, Eq)] // C-COMMON-TRAITS: `Default` (others just so we can test).
struct Default {
    a: block::Version,
    b: &'static Script,
    c: ScriptBuf,
    d: Sequence,
    e: Witness,
}

/// A struct that includes all public error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    a: transaction::ParseOutPointError,
    b: relative::IncompatibleHeightError,
    c: relative::IncompatibleTimeError,
    d: relative::IncompatibleHeightError,
    e: relative::IncompatibleTimeError,
    f: relative::DisabledLockTimeError,
    g: relative::DisabledLockTimeError,
    h: script::RedeemScriptSizeError,
    i: script::WitnessScriptSizeError,
}

#[test]
fn api_can_use_units_modules_from_crate_root() {
    use bitcoin_primitives::{amount, block, fee_rate, locktime, weight};
}

#[test]
fn api_can_use_units_types_from_crate_root() {
    use bitcoin_primitives::{Amount, BlockHeight, BlockInterval, FeeRate, SignedAmount, Weight};
}

#[test]
fn api_can_use_all_units_types_from_module_amount() {
    use bitcoin_primitives::amount::{
        Amount, Denomination, Display, InputTooLargeError, InvalidCharacterError,
        MissingDenominationError, MissingDigitsError, OutOfRangeError, ParseAmountError,
        ParseDenominationError, ParseError, PossiblyConfusingDenominationError, SignedAmount,
        TooPreciseError, UnknownDenominationError,
    };
}

#[test]
fn api_can_use_modules_from_crate_root() {
    use bitcoin_primitives::{
        block, locktime, merkle_tree, pow, script, sequence, transaction, witness,
    };
}

#[test]
fn api_can_use_types_from_crate_root() {
    use bitcoin_primitives::{
        Block, BlockHash, BlockHeader, BlockVersion, CompactTarget, OutPoint, Script, ScriptBuf,
        Sequence, Transaction, TransactionVersion, TxIn, TxMerkleNode, TxOut, Txid, Witness,
        WitnessCommitment, WitnessMerkleNode, Wtxid,
    };
}

#[test]
fn api_can_use_all_types_from_module_locktime() {
    use bitcoin_primitives::locktime::relative::{
        DisabledLockTimeError, IncompatibleHeightError, IncompatibleTimeError, LockTime,
    };
    use bitcoin_primitives::locktime::{absolute, relative};
}

#[test]
fn api_can_use_all_types_from_module_script() {
    use bitcoin_primitives::script::{
        RedeemScriptSizeError, Script, ScriptBuf, ScriptHash, WScriptHash, WitnessScriptSizeError,
    };
}

// `Debug` representation is never empty (C-DEBUG-NONEMPTY).
#[test]
fn api_all_non_error_types_have_non_empty_debug() {
    macro_rules! check_debug {
        ($($t:expr);* $(;)?) => {
            $(
                let debug = format!("{:?}", $t);
                assert!(!debug.is_empty());
            )*
        }
    }

    // All the enums.
    check_debug! {
        absolute::LockTime::ZERO;
        relative::LockTime::ZERO
    };

    // We abuse `Arbitrary` here to get a quick and dirty instance.
    let ab: [u8; 32] = [0xab; 32];
    let mut u = arbitrary::Unstructured::new(&ab);
    let transaction = Transaction::arbitrary(&mut u).unwrap();

    // All the structs.
    check_debug! {
        block::Block::<Unchecked>::arbitrary(&mut u).unwrap().assume_checked(None);
        block::Block::<Unchecked>::arbitrary(&mut u).unwrap();
        block::Header::arbitrary(&mut u).unwrap();
        block::Version::arbitrary(&mut u).unwrap();
        block::BlockHash::from_byte_array(BYTES);
        block::WitnessCommitment::from_byte_array(BYTES);
        merkle_tree::TxMerkleNode::from_byte_array(BYTES);
        merkle_tree::WitnessMerkleNode::from_byte_array(BYTES);
        pow::CompactTarget::from_consensus(0x1d00_ffff);
        SCRIPT.as_script();
        ScriptHash::from_script(&SCRIPT).unwrap();
        WScriptHash::from_script(&SCRIPT).unwrap();
        SCRIPT.clone();
        Sequence::arbitrary(&mut u).unwrap();
        Transaction::arbitrary(&mut u).unwrap();
        TxIn::arbitrary(&mut u).unwrap();
        TxOut::arbitrary(&mut u).unwrap();
        OutPoint::arbitrary(&mut u).unwrap();
        transaction.compute_txid();
        transaction.compute_wtxid();
        transaction.version;
        Witness::arbitrary(&mut u).unwrap();
        // ad: witness::Iter<'a>,
    };
}

#[test]
fn all_types_implement_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Structs>();
    assert_sync::<Structs>();
    assert_send::<Enums>();
    assert_sync::<Enums>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}

#[test]
fn regression_default() {
    let got: Default = Default::default();
    let want = Default {
        a: block::Version::NO_SOFT_FORK_SIGNALLING,
        b: Script::from_bytes(&[]),
        c: ScriptBuf::from_bytes(Vec::new()),
        d: Sequence::MAX,
        e: Witness::new(),
    };
    assert_eq!(got, want);
}

#[test]
// The only trait in this crate is `block::Validation` and it is not dyn compatible.
fn dyn_compatible() {}
