// SPDX-License-Identifier: CC0-1.0

//! Test the API surface (not functionality) of `bitcoin-primitives`.
//!
//! See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html) and the [rust-bitcoin policies](../../docs/policy.md).

#![allow(dead_code)]
#![allow(unused_imports)]
// No benefit in running this test without features enabled.
#![cfg(feature = "alloc")]
#![cfg(feature = "hex")]
#![cfg(feature = "arbitrary")]

use arbitrary::Arbitrary;
use bitcoin_primitives::block::{Checked, Unchecked};
use bitcoin_primitives::script::{
    self, ScriptHash, ScriptPubKeyBufDecoder, ScriptSigBufDecoder, WScriptHash,
};
use bitcoin_primitives::{
    absolute, block, merkle_tree, pow, relative, transaction, witness, OutPoint, RedeemScript,
    RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf, ScriptSig, ScriptSigBuf, Sequence, TapScript,
    TapScriptBuf, Transaction, TxIn, TxOut, Txid, Witness, WitnessScript, WitnessScriptBuf, Wtxid,
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
    j1: &'a RedeemScript,
    j2: &'a ScriptPubKey,
    j3: &'a ScriptSig,
    j4: &'a TapScript,
    j5: &'a WitnessScript,
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Ntxid,
    v: transaction::Version,
    w: Witness,
    // x: witness::Iter<'a>,
}

static REDEEM_SCRIPT: RedeemScriptBuf = RedeemScriptBuf::new();
static SCRIPT_SIG: ScriptSigBuf = ScriptSigBuf::new();
static SCRIPT_PUB_KEY: ScriptPubKeyBuf = ScriptPubKeyBuf::new();
static TAP_SCRIPT: TapScriptBuf = TapScriptBuf::new();
static WITNESS_SCRIPT: WitnessScriptBuf = WitnessScriptBuf::new();
static BYTES: [u8; 32] = [0x00; 32];

/// Public structs that derive common traits.
// C-COMMON-TRAITS excluding `Debug`, `Default`, `Display`, `Ord`, `PartialOrd`, `Hash`.
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
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Ntxid,
    v: transaction::Version,
    w: Witness,
    // x: witness::Iter<'a>,
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
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Ntxid,
    v: transaction::Version,
    w: Witness,
    x: witness::Iter<'a>,
}

/// Public structs that derive common traits.
// C-COMMON-TRAITS excluding `Clone`, `Debug`, `Default`, and `Display`
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
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    n: Sequence,
    o: Transaction,
    p: TxIn,
    q: TxOut,
    r: OutPoint,
    s: Txid,
    t: Wtxid,
    u: transaction::Ntxid,
    v: transaction::Version,
    w: Witness,
    // x: witness::Iter<'a>,
}

/// A struct that includes all types that implement `Default`.
#[derive(Default, Debug, PartialEq, Eq)] // C-COMMON-TRAITS: `Default` (others just so we can test).
struct Default {
    a: block::Version,
    b1: &'static RedeemScript,
    b2: &'static ScriptPubKey,
    b3: &'static ScriptSig,
    b4: &'static TapScript,
    b5: &'static WitnessScript,
    c1: RedeemScriptBuf,
    c2: ScriptPubKeyBuf,
    c3: ScriptSigBuf,
    c4: TapScriptBuf,
    c5: WitnessScriptBuf,
    d: Sequence,
    e: Witness,
}

/// A struct that includes all public decoder types.
#[derive(Default)] // All decoders implement `Default` (P-DECODERS).
struct Decoders {
    a: block::BlockDecoder,
    b: block::BlockHashDecoder,
    c: block::HeaderDecoder,
    d: block::VersionDecoder,
    e: merkle_tree::TxMerkleNodeDecoder,
    f: ScriptPubKeyBufDecoder,
    g: ScriptSigBufDecoder,
    h: transaction::TransactionDecoder,
    i: transaction::TxInDecoder,
    j: transaction::TxOutDecoder,
    k: transaction::OutPointDecoder,
    l: transaction::VersionDecoder,
    m: witness::WitnessDecoder,
}

/// A struct that includes all public error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    a: transaction::ParseOutPointError,
    b: relative::error::DisabledLockTimeError,
    c: relative::error::IsSatisfiedByError,
    d: relative::error::IsSatisfiedByHeightError,
    e: relative::error::IsSatisfiedByTimeError,
    f: script::RedeemScriptSizeError,
    g: script::WitnessScriptSizeError,
}

/// C-DEBUG-NONEMPTY: Tests that all public non-error types have non-empty Debug.
#[test]
fn c_debug_nonempty() {
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
        pow::CompactTarget::arbitrary(&mut u).unwrap();
        REDEEM_SCRIPT.as_script();
        SCRIPT_SIG.as_script();
        SCRIPT_PUB_KEY.as_script();
        TAP_SCRIPT.as_script();
        WITNESS_SCRIPT.as_script();
        ScriptHash::from_script(&REDEEM_SCRIPT).unwrap();
        WScriptHash::from_script(&WITNESS_SCRIPT).unwrap();
        REDEEM_SCRIPT.clone();
        SCRIPT_SIG.clone();
        SCRIPT_PUB_KEY.clone();
        TAP_SCRIPT.clone();
        WITNESS_SCRIPT.clone();
        Sequence::arbitrary(&mut u).unwrap();
        Transaction::arbitrary(&mut u).unwrap();
        TxIn::arbitrary(&mut u).unwrap();
        TxOut::arbitrary(&mut u).unwrap();
        OutPoint::arbitrary(&mut u).unwrap();
        transaction.compute_txid();
        transaction.compute_wtxid();
        transaction.compute_ntxid();
        transaction.version;
        Witness::arbitrary(&mut u).unwrap();
        // ad: witness::Iter<'a>,
    };
}

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn c_send_sync() {
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

/// C-OBJECT: Tests that traits are object-safe where appropriate.
#[test]
fn c_object() {
    // If this builds then traits are dyn compatible.
    struct Traits {
        // These traits are explicitly not dyn compatible.
        // a: Box<dyn block::Validation>,
    }
}

/// C-GOOD-ERR: Tests that all public error types implement Display.
#[test]
fn c_good_err_display() {
    use core::fmt;

    fn assert_display<T: fmt::Display>() {}

    assert_display::<transaction::ParseOutPointError>();
    assert_display::<relative::error::DisabledLockTimeError>();
    assert_display::<relative::error::IsSatisfiedByError>();
    assert_display::<relative::error::IsSatisfiedByHeightError>();
    assert_display::<relative::error::IsSatisfiedByTimeError>();
    assert_display::<script::RedeemScriptSizeError>();
    assert_display::<script::WitnessScriptSizeError>();
}

/// C-SERDE: Tests that serde traits are implemented where expected.
#[test]
#[cfg(feature = "serde")]
fn c_serde() {
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

    assert_serde::<block::Version>();
    assert_serde::<transaction::Version>();
    assert_serde::<OutPoint>();
    assert_serde::<Witness>();
}

/// P-DEFAULT-CHANGE: Tests regression for Default implementation values.
#[test]
fn p_default_change() {
    let got: Default = Default::default();
    let want = Default {
        a: block::Version::NO_SOFT_FORK_SIGNALLING,
        b1: RedeemScript::from_bytes(&[]),
        b2: ScriptPubKey::from_bytes(&[]),
        b3: ScriptSig::from_bytes(&[]),
        b4: TapScript::from_bytes(&[]),
        b5: WitnessScript::from_bytes(&[]),
        c1: RedeemScriptBuf::from_bytes(Vec::new()),
        c2: ScriptPubKeyBuf::from_bytes(Vec::new()),
        c3: ScriptSigBuf::from_bytes(Vec::new()),
        c4: TapScriptBuf::from_bytes(Vec::new()),
        c5: WitnessScriptBuf::from_bytes(Vec::new()),
        d: Sequence::MAX,
        e: Witness::new(),
    };
    assert_eq!(got, want);
}

/// P-DECODERS: Tests that decoders implement a constructor method.
#[test]
fn p_decoders_implement_new() {
    let _ = block::BlockDecoder::new();
    let _ = block::BlockHashDecoder::new();
    let _ = block::HeaderDecoder::new();
    let _ = block::VersionDecoder::new();
    let _ = merkle_tree::TxMerkleNodeDecoder::new();
    let _ = ScriptPubKeyBufDecoder::new();
    let _ = ScriptSigBufDecoder::new();
    let _ = transaction::TransactionDecoder::new();
    let _ = transaction::TxInDecoder::new();
    let _ = transaction::TxOutDecoder::new();
    let _ = transaction::OutPointDecoder::new();
    let _ = transaction::VersionDecoder::new();
    let _ = witness::WitnessDecoder::new();
}

/// P-CONSISTENT-EXPORTS: Tests that units modules can be used from the crate root.
#[test]
fn p_consistent_exports_units_modules() {
    use bitcoin_primitives::{amount, block, fee_rate, locktime, weight};
}

/// P-CONSISTENT-EXPORTS: Tests that units type aliases can be used from the crate root.
#[test]
fn p_consistent_exports_units_types() {
    use bitcoin_primitives::{
        Amount, BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate,
        NumOpResult, Sequence, SignedAmount, Weight,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all units types can be imported from the `amount` module.
#[test]
fn p_consistent_exports_units_amount() {
    use bitcoin_primitives::amount::{
        Amount, Denomination, Display, OutOfRangeError, ParseAmountError, ParseDenominationError,
        ParseError, SignedAmount,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all units types can be imported from the `amount::error` module.
#[test]
fn p_consistent_exports_units_amount_error() {
    use bitcoin_primitives::amount::error::{
        InputTooLargeError, InvalidCharacterError, MissingDenominationError, MissingDigitsError,
        OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError,
        PossiblyConfusingDenominationError, TooPreciseError, UnknownDenominationError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that modules can be used from the crate root.
#[test]
fn p_consistent_exports_crate_modules() {
    use bitcoin_primitives::{
        amount, block, fee_rate, locktime, merkle_tree, parse_int, pow, result, script, sequence,
        time, transaction, weight, witness,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that type aliases can be used from the crate root.
#[test]
fn p_consistent_exports_crate_types() {
    use bitcoin_primitives::{
        Block, BlockChecked, BlockHash, BlockHeader, BlockUnchecked, BlockValidation, BlockVersion,
        CompactTarget, OutPoint, RedeemScript, RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf,
        ScriptSig, ScriptSigBuf, Sequence, TapScript, TapScriptBuf, Transaction,
        TransactionVersion, TxIn, TxOut, Txid, Witness, WitnessCommitment, WitnessScript,
        WitnessScriptBuf, Wtxid,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime` module.
#[test]
fn p_consistent_exports_locktime() {
    use bitcoin_primitives::locktime::relative::error::{
        DisabledLockTimeError, InvalidHeightError, InvalidTimeError,
    };
    use bitcoin_primitives::locktime::relative::LockTime;
    use bitcoin_primitives::locktime::{absolute, relative};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `script` module.
#[test]
fn p_consistent_exports_script() {
    use bitcoin_primitives::script::{
        RedeemScriptSizeError, ScriptBufDecoder, ScriptBufDecoderError, ScriptEncoder, ScriptHash,
        ScriptPubKey, ScriptPubKeyBuf, ScriptSig, ScriptSigBuf, WScriptHash,
        WitnessScriptSizeError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `block` module.
#[test]
fn p_consistent_exports_block() {
    use bitcoin_primitives::block::{
        BlockDecoder, BlockDecoderError, BlockEncoder, BlockHashDecoder, BlockHashDecoderError,
        BlockHashEncoder, HeaderDecoder, HeaderEncoder, VersionDecoder, VersionDecoderError,
        VersionEncoder,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `merkle_tree` module.
#[test]
fn p_consistent_exports_merkle_tree() {
    use bitcoin_primitives::merkle_tree::{
        TxMerkleNodeDecoder, TxMerkleNodeDecoderError, TxMerkleNodeEncoder,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `transaction` module.
#[test]
fn p_consistent_exports_transaction() {
    use bitcoin_primitives::transaction::{
        OutPointDecoder, OutPointDecoderError, OutPointEncoder, TransactionDecoder,
        TransactionDecoderError, TransactionEncoder, TxInDecoder, TxInDecoderError, TxInEncoder,
        TxOutDecoder, TxOutDecoderError, TxOutEncoder, VersionDecoder, VersionDecoderError,
        VersionEncoder,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `witness` module.
#[test]
fn p_consistent_exports_witness() {
    use bitcoin_primitives::witness::{WitnessDecoder, WitnessDecoderError, WitnessEncoder};
}
