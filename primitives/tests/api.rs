// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `units`.
//!
//! The point of these tests are to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]
#![cfg(feature = "alloc")]
#![cfg(feature = "arbitrary")]

use arbitrary::Arbitrary;
use bitcoin_primitives as primitives;
use hashes::sha256t;
use primitives::block::{Checked, Unchecked};
use primitives::script::{self, ScriptHash, WScriptHash};
use primitives::taproot::{TapBranchTag, TapLeafTag, TapTweakTag};
use primitives::{
    absolute, block, merkle_tree, opcodes, pow, relative, taproot, transaction, witness, OutPoint, Script,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, Wtxid,
};

/// A struct that includes all public non-error enums.
// Verify with: `git grep 'pub enum' | grep -v Error`
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: absolute::LockTime,
    b: relative::LockTime,
    c: opcodes::Class,
    d: opcodes::ClassifyContext,
    e: opcodes::Ordinary,
    // block::Checked, // Empty enums cannot be constructed.
    // block::Unchecked,
}

impl Enums {
    fn new() -> Self {
        Self {
            a: absolute::LockTime::ZERO,
            b: relative::LockTime::ZERO,
            c: opcodes::Class::PushNum(0),
            d: opcodes::ClassifyContext::TapScript,
            e: opcodes::Ordinary::OP_CHECKSIGADD,
        }
    }
}

/// A struct that includes all public non-error structs.
// Verify with: `git grep 'pub struct' | grep -v Error`
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
    i: opcodes::Opcode,
    j: pow::CompactTarget,
    k: &'a Script,
    l: ScriptHash,
    m: WScriptHash,
    n: ScriptBuf,
    o: Sequence,
    leaf: TapLeafTag,
    p: taproot::TapLeafHash,
    branch: TapBranchTag,
    q: taproot::TapNodeHash,
    tweak: TapTweakTag,
    r: taproot::TapTweakHash,
    s: Transaction,
    t: TxIn,
    u: TxOut,
    v: OutPoint,
    w: Txid,
    x: Wtxid,
    y: transaction::Version,
    z: Witness,
    iter: witness::Iter<'a>,
}

static SCRIPT: ScriptBuf = ScriptBuf::new();
static BYTES: [u8; 32] = [0x00; 32];
static WITNESS: Witness = Witness::new();

impl Structs<'_> {
    /// Constructs a new arbitrary-ish instance.
    fn new() -> Self {
        // We abuse `Arbitrary` here to get a quick and dirty instance.
        let mut ab: [u8; 32] = [0xab; 32];
        let mut u = arbitrary::Unstructured::new(&mut ab);
        let transaction = Transaction::arbitrary(&mut u).unwrap();

        Self {
            a: block::Block::<Unchecked>::arbitrary(&mut u).unwrap().assume_checked(None),
            b: block::Block::<Unchecked>::arbitrary(&mut u).unwrap(),
            c: block::Header::arbitrary(&mut u).unwrap(),
            d: block::Version::arbitrary(&mut u).unwrap(),
            e: block::BlockHash::from_byte_array(BYTES),
            f: block::WitnessCommitment::from_byte_array(BYTES),
            g: merkle_tree::TxMerkleNode::from_byte_array(BYTES),
            h: merkle_tree::WitnessMerkleNode::from_byte_array(BYTES),
            i: opcodes::OP_TRUE,
            j: pow::CompactTarget::from_consensus(0x1d00ffff),
            k: SCRIPT.as_script(),
            l: ScriptHash::from_script(&SCRIPT).unwrap(),
            m: WScriptHash::from_script(&SCRIPT).unwrap(),
            n: SCRIPT.clone(),
            o: Sequence::arbitrary(&mut u).unwrap(),
            leaf: TapLeafTag {},
            p: taproot::TapLeafHash::from_byte_array(BYTES),
            branch: TapBranchTag {},
            q: taproot::TapNodeHash::from_byte_array(BYTES),
            tweak: TapTweakTag {},
            r: taproot::TapTweakHash::from_byte_array(BYTES),
            s: Transaction::arbitrary(&mut u).unwrap(),
            t: TxIn::arbitrary(&mut u).unwrap(),
            u: TxOut::arbitrary(&mut u).unwrap(),
            v: OutPoint::arbitrary(&mut u).unwrap(),
            w: transaction.compute_txid(),
            x: transaction.compute_wtxid(),
            y: transaction.version,
            z: Witness::arbitrary(&mut u).unwrap(),
            iter: WITNESS.iter(),
        }
    }
}

/// All the sha256t hash tags.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)] // C-COMMON-TRAITS
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Tags {
    leaf: sha256t::Hash<TapLeafTag>,
    branch: sha256t::Hash<TapBranchTag>,
    tweak: sha256t::Hash<TapTweakTag>,
}

impl Tags {
    fn new() -> Self {
        Self {
            leaf: sha256t::Hash::<TapLeafTag>::hash(&[]),
            branch: sha256t::Hash::<TapBranchTag>::hash(&[]),
            tweak: sha256t::Hash::<TapTweakTag>::hash(&[]),
        }
    }
}

/// A struct that includes all public non-error types.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Types {
    a: Enums,
    b: Structs<'static>,
    c: Tags,
}

impl Types {
    fn new() -> Self { Self { a: Enums::new(), b: Structs::new(), c: Tags::new() } }
}

/// Public structs that derive common traits.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)] // C-COMMON-TRAITS
struct CommonTraitsOrd {
    // a: block::Block<Checked>,  // See `CommonTraitsNoOrd`.
    // b: block::Block<Unchecked>,  // See `CommonTraitsNoOrd`.
    c: block::Header,
    d: block::Version,
    e: block::BlockHash,
    f: block::WitnessCommitment,
    g: merkle_tree::TxMerkleNode,
    h: merkle_tree::WitnessMerkleNode,
    // i: opcodes::Opcode,  // See `CommonTraitsNoOrd`.
    j: pow::CompactTarget,
    // k: &'a Script,  // See `CommonTraitsNoOrd`.
    l: ScriptHash,
    m: WScriptHash,
    n: ScriptBuf,
    o: Sequence,
    leaf: TapLeafTag,
    p: taproot::TapLeafHash,
    branch: TapBranchTag,
    q: taproot::TapNodeHash,
    tweak: TapTweakTag,
    r: taproot::TapTweakHash,
    s: Transaction,
    t: TxIn,
    u: TxOut,
    v: OutPoint,
    w: Txid,
    x: Wtxid,
    y: transaction::Version,
    z: Witness,
    // iter: witness::Iter<'a>, // Only implements `Debug`.
}

/// Public structs that derive common traits - excluding `Ord` and friends.
#[derive(Clone, PartialEq, Eq)] // C-COMMON-TRAITS
struct CommonTraitsNoOrd<'a> {
    a: block::Block<Checked>,
    b: block::Block<Unchecked>,
    i: opcodes::Opcode,
    k: &'a Script,
}

/// A struct that includes all types that implement `Default`.
#[derive(Debug, Default, PartialEq, Eq)] // C-COMMON-TRAITS: `Default`
struct Default {
    d: block::Version,
    l: &'static Script,
    n: ScriptBuf,
    o: Sequence,
    z: Witness,
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
        block, locktime, merkle_tree, opcodes, pow, script, sequence, taproot, transaction, witness,
    };
}

#[test]
fn api_can_use_types_from_crate_root() {
    use bitcoin_primitives::{
        Block, BlockHash, BlockHeader, BlockVersion, CompactTarget, Opcode, OutPoint, Script,
        ScriptBuf, ScriptHash, Sequence, TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash,
        TapTweakHash, TapTweakTag, Transaction, TxIn, TxMerkleNode, TxOut, TxVersion, Txid,
        WScriptHash, Witness, WitnessCommitment, WitnessMerkleNode, Wtxid,
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
        ($t:tt, $field:tt; $($sub_field:tt),* $(,)?) => {
            $(
                let debug = format!("{:?}", $t.$field.$sub_field);
                assert!(!debug.is_empty());
            )*
        }
    }

    let t = Types::new();

    check_debug!(t, a; a, b, c, d);
    check_debug!(t, b; a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, iter);
    check_debug!(t, c; leaf, branch, tweak);
}

#[test]
fn all_types_implement_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Types>();
    assert_sync::<Types>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}

#[test]
fn regression_default() {
    let got: Default = Default::default();
    let want = Default {
        d: block::Version::NO_SOFT_FORK_SIGNALLING,
        l: Script::from_bytes(&[]),
        n: ScriptBuf::from_bytes(Vec::new()),
        o: Sequence::MAX,
        z: Witness::new(),   // This probably does not prove anything?
    };
    assert_eq!(got, want);
}

#[test]
fn dyn_compatible() {
    // If this builds then traits are dyn compatible.
    struct Traits {
        // a: Box<dyn block::Validation>,
    }
}
