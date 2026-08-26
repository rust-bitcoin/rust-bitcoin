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

extern crate alloc;

use arbitrary::Arbitrary;
use bitcoin_primitives::block::{Checked, Unchecked};
use bitcoin_primitives::script::{
    self, Builder, PushBytes, PushBytesBuf, RedeemScriptTag, ScriptHash, ScriptPubKeyBufDecoder,
    ScriptPubKeyTag, ScriptSigBufDecoder, ScriptSigTag, SignetBlockScriptTag, TapScriptTag,
    WScriptHash, WitnessScriptTag,
};
use bitcoin_primitives::{
    block, merkle_tree, opcodes, transaction, witness, witness_version, OutPoint, RedeemScript,
    RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf, ScriptSig, ScriptSigBuf, SignetBlockScript,
    SignetBlockScriptBuf, TapScript, TapScriptBuf, Transaction, TxIn, TxOut, Txid, Witness,
    WitnessScript, WitnessScriptBuf, Wtxid,
};

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: block::Checked, // Empty enums are not constructable.
    b: block::Unchecked,
    e: script::RedeemScriptTag, // Script tags are empty enums.
    f: script::ScriptPubKeyTag,
    g: script::ScriptSigTag,
    h: script::SignetBlockScriptTag,
    i: script::TapScriptTag,
    j: script::WitnessScriptTag,
    k: witness_version::WitnessVersion,
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
    j1: &'a RedeemScript,
    j2: &'a ScriptPubKey,
    j3: &'a ScriptSig,
    j4: &'a TapScript,
    j5: &'a WitnessScript,
    j6: &'a SignetBlockScript,
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    m6: SignetBlockScriptBuf,
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
    y: Builder<ScriptSigTag>,
    z1: &'a PushBytes,
    z2: PushBytesBuf,
    aa: opcodes::Opcode,
}

static REDEEM_SCRIPT: RedeemScriptBuf = RedeemScriptBuf::new();
static SCRIPT_SIG: ScriptSigBuf = ScriptSigBuf::new();
static SCRIPT_PUB_KEY: ScriptPubKeyBuf = ScriptPubKeyBuf::new();
static SIGNET_BLOCK_SCRIPT: SignetBlockScriptBuf = SignetBlockScriptBuf::new();
static TAP_SCRIPT: TapScriptBuf = TapScriptBuf::new();
static WITNESS_SCRIPT: WitnessScriptBuf = WitnessScriptBuf::new();
static PUSH_BYTES: PushBytesBuf = PushBytesBuf::new();
static BYTES: [u8; 32] = [0x00; 32];

/// Public structs that derive common traits.
// C-COMMON-TRAITS excluding `Copy`, `Debug`, `Default`, `Display`, `Ord`, `PartialOrd`, `Hash`.
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
    // j: &'a Script,
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    m6: SignetBlockScriptBuf,
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
    y: Builder<ScriptSigTag>,
    z: PushBytesBuf,
    aa: opcodes::Opcode,
    ad: witness_version::WitnessVersion,
    ae1: script::RedeemScriptTag,
    ae2: script::ScriptPubKeyTag,
    ae3: script::ScriptSigTag,
    ae4: script::SignetBlockScriptTag,
    ae5: script::TapScriptTag,
    ae6: script::WitnessScriptTag,
    af1: block::Checked,
    af2: block::Unchecked,
}

/// A struct that includes all types that implement `Copy`.
#[derive(Copy, Clone)] // C-COMMON-TRAITS: `Copy`
struct Copy {
    a: block::Header,
    b: block::Version,
    c: block::BlockHash,
    d: block::WitnessCommitment,
    e: merkle_tree::TxMerkleNode,
    f: merkle_tree::WitnessMerkleNode,
    h: ScriptHash,
    i: WScriptHash,
    k: OutPoint,
    l: Txid,
    m: Wtxid,
    n: transaction::Ntxid,
    o: transaction::Version,
    p: opcodes::Opcode,
    s: witness_version::WitnessVersion,
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
    // j: &'a Script,
    j0: alloc::boxed::Box<PushBytes>,
    j1: alloc::boxed::Box<RedeemScript>,
    j2: alloc::boxed::Box<ScriptPubKey>,
    j3: alloc::boxed::Box<ScriptSig>,
    j4: alloc::boxed::Box<TapScript>,
    j5: alloc::boxed::Box<WitnessScript>,
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    m6: SignetBlockScriptBuf,
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
    y: Builder<ScriptSigTag>,
    z: PushBytesBuf,
    aa: opcodes::Opcode,
    ad: witness_version::WitnessVersion,
    ae1: script::RedeemScriptTag,
    ae2: script::ScriptPubKeyTag,
    ae3: script::ScriptSigTag,
    ae4: script::SignetBlockScriptTag,
    ae5: script::TapScriptTag,
    ae6: script::WitnessScriptTag,
    af1: block::Checked,
    af2: block::Unchecked,
}

/// Public structs that derive common traits.
// C-COMMON-TRAITS excluding `Clone`, `Copy`, `Debug`, `Default`, and `Display`
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
    // j: &'a Script,  // Doesn't implement `Clone`.
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: TapScriptBuf,
    m5: WitnessScriptBuf,
    m6: SignetBlockScriptBuf,
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
    // y: Builder<ScriptSigTag>, // Doesn't implement `Ord` or `Hash`.
    z: PushBytesBuf,
    // aa: opcodes::Opcode, // Deliberately does not implement `Ord` (see type docs).
    ad: witness_version::WitnessVersion,
    ae1: script::RedeemScriptTag,
    ae2: script::ScriptPubKeyTag,
    ae3: script::ScriptSigTag,
    ae4: script::SignetBlockScriptTag,
    ae5: script::TapScriptTag,
    ae6: script::WitnessScriptTag,
    af1: block::Checked,
    af2: block::Unchecked,
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
    b6: &'static SignetBlockScript,
    c1: RedeemScriptBuf,
    c2: ScriptPubKeyBuf,
    c3: ScriptSigBuf,
    c4: TapScriptBuf,
    c5: WitnessScriptBuf,
    c6: SignetBlockScriptBuf,
    e: Witness,
    f: Builder<ScriptSigTag>,
    g: PushBytesBuf,
}

/// A struct that includes all public encoder types.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Encoders<'a> {
    a: block::BlockEncoder<'a>,
    b: block::BlockHashEncoder<'a>,
    c: block::HeaderEncoder<'a>,
    d: block::VersionEncoder<'a>,
    e: merkle_tree::TxMerkleNodeEncoder<'a>,
    f: script::ScriptEncoder<'a>,
    g: transaction::OutPointEncoder<'a>,
    h: transaction::TransactionEncoder<'a>,
    i: transaction::TxInEncoder<'a>,
    j: transaction::TxOutEncoder<'a>,
    k: transaction::VersionEncoder<'a>,
    l: witness::WitnessEncoder<'a>,
}

/// A struct that includes all public decoder types.
// All public types implement `Debug` (C-DEBUG), all decoders implement `Default` (P-DECODERS).
#[derive(Debug, Default)]
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
    a: block::BlockDecoderError,
    b: block::BlockHashDecoderError,
    d: block::HeaderDecoderError,
    e: block::InvalidBlockError,
    g: block::VersionDecoderError,
    h: merkle_tree::TxMerkleNodeDecoderError,
    m: script::PushBytesError,
    n: script::RedeemScriptSizeError,
    o: script::ScriptBufDecoderError,
    p: script::WitnessScriptSizeError,
    q: transaction::OutPointDecoderError,
    r: transaction::ParseOutPointError,
    s: transaction::TransactionDecoderError,
    t: transaction::TxInDecoderError,
    u: transaction::TxOutDecoderError,
    v: transaction::VersionDecoderError,
    w: witness::UnexpectedEofError,
    x: witness::WitnessDecoderError,
    y: witness_version::InvalidWitnessVersionError,
    z: witness_version::ParseWitnessVersionError,
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
        witness_version::WitnessVersion::V0
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
        REDEEM_SCRIPT.as_script();
        SCRIPT_SIG.as_script();
        SCRIPT_PUB_KEY.as_script();
        SIGNET_BLOCK_SCRIPT.as_script();
        TAP_SCRIPT.as_script();
        WITNESS_SCRIPT.as_script();
        ScriptHash::from_script(&REDEEM_SCRIPT).unwrap();
        WScriptHash::from_script(&WITNESS_SCRIPT).unwrap();
        REDEEM_SCRIPT.clone();
        SCRIPT_SIG.clone();
        SCRIPT_PUB_KEY.clone();
        SIGNET_BLOCK_SCRIPT.clone();
        TAP_SCRIPT.clone();
        WITNESS_SCRIPT.clone();
        Transaction::arbitrary(&mut u).unwrap();
        TxIn::arbitrary(&mut u).unwrap();
        TxOut::arbitrary(&mut u).unwrap();
        OutPoint::arbitrary(&mut u).unwrap();
        transaction.compute_txid();
        transaction.compute_wtxid();
        transaction.compute_ntxid();
        transaction.version;
        Witness::arbitrary(&mut u).unwrap();
        Witness::arbitrary(&mut u).unwrap().iter();
        Builder::<ScriptSigTag>::new();
        PUSH_BYTES.as_push_bytes();
        PUSH_BYTES.clone();
        opcodes::Opcode::from_u8(0x51);
    };

    // All the decoders.
    check_debug! {
        block::BlockDecoder::new();
        block::BlockHashDecoder::new();
        block::HeaderDecoder::new();
        block::VersionDecoder::new();
        merkle_tree::TxMerkleNodeDecoder::new();
        ScriptPubKeyBufDecoder::new();
        ScriptSigBufDecoder::new();
        transaction::OutPointDecoder::new();
        transaction::TransactionDecoder::new();
        transaction::TxInDecoder::new();
        transaction::TxOutDecoder::new();
        transaction::VersionDecoder::new();
        witness::WitnessDecoder::new();
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
    assert_send::<Encoders>();
    assert_sync::<Encoders>();
    assert_send::<Decoders>();
    assert_sync::<Decoders>();

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
        b: alloc::boxed::Box<dyn script::PushBytesErrorReport>,
        c: alloc::boxed::Box<dyn script::ScriptHashableTag>,
        d: alloc::boxed::Box<dyn script::Tag>,
    }
}

/// C-GOOD-ERR: Tests that all public error types implement Display.
#[test]
fn c_good_err_display() {
    use core::fmt;

    fn assert_display<T: fmt::Display>() {}

    assert_display::<block::BlockDecoderError>();
    assert_display::<block::BlockHashDecoderError>();
    assert_display::<block::HeaderDecoderError>();
    assert_display::<block::InvalidBlockError>();
    assert_display::<block::VersionDecoderError>();
    assert_display::<merkle_tree::TxMerkleNodeDecoderError>();
    assert_display::<script::PushBytesError>();
    assert_display::<script::RedeemScriptSizeError>();
    assert_display::<script::ScriptBufDecoderError>();
    assert_display::<script::WitnessScriptSizeError>();
    assert_display::<transaction::OutPointDecoderError>();
    assert_display::<transaction::ParseOutPointError>();
    assert_display::<transaction::TransactionDecoderError>();
    assert_display::<transaction::TxInDecoderError>();
    assert_display::<transaction::TxOutDecoderError>();
    assert_display::<transaction::VersionDecoderError>();
    assert_display::<witness::UnexpectedEofError>();
    assert_display::<witness::WitnessDecoderError>();
    assert_display::<witness_version::InvalidWitnessVersionError>();
    assert_display::<witness_version::ParseWitnessVersionError>();
}

/// C-SERDE: Tests that serde traits are implemented where expected.
#[test]
#[cfg(feature = "serde")]
fn c_serde() {
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

    assert_serde::<block::BlockHash>();
    assert_serde::<block::Version>();
    assert_serde::<block::WitnessCommitment>();
    assert_serde::<merkle_tree::TxMerkleNode>();
    assert_serde::<merkle_tree::WitnessMerkleNode>();
    assert_serde::<RedeemScriptBuf>();
    assert_serde::<ScriptPubKeyBuf>();
    assert_serde::<ScriptSigBuf>();
    assert_serde::<SignetBlockScriptBuf>();
    assert_serde::<TapScriptBuf>();
    assert_serde::<WitnessScriptBuf>();
    assert_serde::<ScriptHash>();
    assert_serde::<WScriptHash>();
    assert_serde::<Txid>();
    assert_serde::<Wtxid>();
    assert_serde::<transaction::Ntxid>();
    assert_serde::<transaction::Version>();
    assert_serde::<OutPoint>();
    assert_serde::<Witness>();
    assert_serde::<witness_version::WitnessVersion>();
}

/// P-ARBITRARY: Tests that public types implement `Arbitrary`.
#[test]
fn p_arbitrary() {
    fn assert_arbitrary<T: for<'a> Arbitrary<'a>>() {}

    assert_arbitrary::<block::Block<Unchecked>>();
    assert_arbitrary::<block::Header>();
    assert_arbitrary::<block::Version>();
    assert_arbitrary::<block::BlockHash>();
    assert_arbitrary::<block::WitnessCommitment>();
    assert_arbitrary::<merkle_tree::TxMerkleNode>();
    assert_arbitrary::<merkle_tree::WitnessMerkleNode>();
    assert_arbitrary::<RedeemScriptBuf>();
    assert_arbitrary::<ScriptPubKeyBuf>();
    assert_arbitrary::<ScriptSigBuf>();
    assert_arbitrary::<TapScriptBuf>();
    assert_arbitrary::<WitnessScriptBuf>();
    assert_arbitrary::<SignetBlockScriptBuf>();
    assert_arbitrary::<ScriptHash>();
    assert_arbitrary::<WScriptHash>();
    assert_arbitrary::<Transaction>();
    assert_arbitrary::<TxIn>();
    assert_arbitrary::<TxOut>();
    assert_arbitrary::<OutPoint>();
    assert_arbitrary::<Txid>();
    assert_arbitrary::<Wtxid>();
    assert_arbitrary::<transaction::Ntxid>();
    assert_arbitrary::<transaction::Version>();
    assert_arbitrary::<Witness>();
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
        b6: SignetBlockScript::from_bytes(&[]),
        c1: RedeemScriptBuf::from_bytes(Vec::new()),
        c2: ScriptPubKeyBuf::from_bytes(Vec::new()),
        c3: ScriptSigBuf::from_bytes(Vec::new()),
        c4: TapScriptBuf::from_bytes(Vec::new()),
        c5: WitnessScriptBuf::from_bytes(Vec::new()),
        c6: SignetBlockScriptBuf::from_bytes(Vec::new()),
        e: Witness::new(),
        f: Builder::new(),
        g: PushBytesBuf::new(),
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
    use bitcoin_primitives::{
        amount, block, fee_rate, locktime, parse_int, pow, result, sequence, time, weight,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that units type aliases can be used from the crate root.
#[test]
fn p_consistent_exports_units_types() {
    use bitcoin_primitives::{
        Amount, BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime,
        CompactTarget, FeeRate, NumOpResult, Sequence, SignedAmount, Target, Weight, Work,
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
        amount, block, fee_rate, locktime, merkle_tree, opcodes, parse_int, pow, result, script,
        sequence, time, transaction, weight, witness, witness_version,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that type aliases can be used from the crate root.
#[test]
fn p_consistent_exports_crate_types() {
    use bitcoin_primitives::{
        Block, BlockChecked, BlockHash, BlockHeader, BlockUnchecked, BlockValidation, BlockVersion,
        CompactTarget, OutPoint, RedeemScript, RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf,
        ScriptSig, ScriptSigBuf, Sequence, SignetBlockScript, SignetBlockScriptBuf, TapScript,
        TapScriptBuf, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
        WitnessCommitment, WitnessScript, WitnessScriptBuf, Wtxid,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime` module.
#[test]
fn p_consistent_exports_locktime() {
    use bitcoin_primitives::locktime::{absolute, relative};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime::absolute` module.
#[test]
fn p_consistent_exports_locktime_absolute() {
    use bitcoin_primitives::locktime::absolute::error::{
        ConversionError as _, IncompatibleHeightError as _, IncompatibleTimeError as _,
        LockTimeDecoderError as _, ParseHeightError as _, ParseTimeError as _,
    };
    use bitcoin_primitives::locktime::absolute::{
        ConversionError, Height, IncompatibleHeightError, IncompatibleTimeError, LockTime,
        LockTimeDecoder, LockTimeDecoderError, LockTimeEncoder, MedianTimePast, ParseHeightError,
        ParseTimeError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime::relative` module.
#[test]
fn p_consistent_exports_locktime_relative() {
    use bitcoin_primitives::locktime::relative::error::{
        DisabledLockTimeError as _, IncompatibleHeightError as _, IncompatibleTimeError as _,
        InvalidHeightError as _, InvalidTimeError as _, IsSatisfiedByError as _,
        IsSatisfiedByHeightError as _, IsSatisfiedByTimeError as _, TimeOverflowError as _,
    };
    use bitcoin_primitives::locktime::relative::{
        DisabledLockTimeError, IncompatibleHeightError, IncompatibleTimeError, InvalidHeightError,
        InvalidTimeError, IsSatisfiedByError, IsSatisfiedByHeightError, IsSatisfiedByTimeError,
        LockTime, NumberOf512Seconds, NumberOfBlocks, TimeOverflowError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `script` module.
#[test]
fn p_consistent_exports_script() {
    use bitcoin_primitives::script::error::{
        PushBytesError as _, RedeemScriptSizeError as _, ScriptBufDecoderError as _,
        WitnessScriptSizeError as _,
    };
    use bitcoin_primitives::script::{
        Builder, PushBytes, PushBytesBuf, PushBytesError, PushBytesErrorReport, RedeemScript,
        RedeemScriptBuf, RedeemScriptSizeError, RedeemScriptTag, Script, ScriptBuf,
        ScriptBufDecoder, ScriptBufDecoderError, ScriptEncoder, ScriptHash, ScriptHashableTag,
        ScriptPubKey, ScriptPubKeyBuf, ScriptPubKeyBufDecoder, ScriptPubKeyTag, ScriptSig,
        ScriptSigBuf, ScriptSigBufDecoder, ScriptSigTag, SignetBlockScript, SignetBlockScriptBuf,
        SignetBlockScriptTag, Tag, TapScript, TapScriptBuf, TapScriptTag, WScriptHash,
        WitnessScript, WitnessScriptBuf, WitnessScriptSizeError, WitnessScriptTag,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `block` module.
#[test]
fn p_consistent_exports_block() {
    use bitcoin_primitives::block::error::{
        BlockDecoderError as _, BlockHashDecoderError as _, BlockHeightDecoderError as _,
        HeaderDecoderError as _, InvalidBlockError as _, TooBigForRelativeHeightError as _,
        VersionDecoderError as _,
    };
    use bitcoin_primitives::block::{
        Block, BlockDecoder, BlockDecoderError, BlockEncoder, BlockHash, BlockHashDecoder,
        BlockHashDecoderError, BlockHashEncoder, BlockHeight, BlockHeightDecoder,
        BlockHeightDecoderError, BlockHeightEncoder, BlockHeightInterval, BlockMtp,
        BlockMtpInterval, Checked, Header, HeaderDecoder, HeaderDecoderError, HeaderEncoder,
        InvalidBlockError, TooBigForRelativeHeightError, Unchecked, Validation, Version,
        VersionDecoder, VersionDecoderError, VersionEncoder, WitnessCommitment,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `merkle_tree` module.
#[test]
fn p_consistent_exports_merkle_tree() {
    use bitcoin_primitives::merkle_tree::error::TxMerkleNodeDecoderError as _;
    use bitcoin_primitives::merkle_tree::{
        TxMerkleNode, TxMerkleNodeDecoder, TxMerkleNodeDecoderError, TxMerkleNodeEncoder,
        WitnessMerkleNode,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `opcodes` module.
#[test]
fn p_consistent_exports_opcodes() {
    use bitcoin_primitives::opcodes::{all, Opcode};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `transaction` module.
#[test]
fn p_consistent_exports_transaction() {
    use bitcoin_primitives::transaction::error::{
        OutPointDecoderError as _, ParseOutPointError as _, TransactionDecoderError as _,
        TxInDecoderError as _, TxOutDecoderError as _, VersionDecoderError as _,
    };
    use bitcoin_primitives::transaction::{
        Ntxid, OutPoint, OutPointDecoder, OutPointDecoderError, OutPointEncoder,
        ParseOutPointError, Transaction, TransactionDecoder, TransactionDecoderError,
        TransactionEncoder, TxIn, TxInDecoder, TxInDecoderError, TxInEncoder, TxOut, TxOutDecoder,
        TxOutDecoderError, TxOutEncoder, Txid, Version, VersionDecoder, VersionDecoderError,
        VersionEncoder, Wtxid,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `witness` module.
#[test]
fn p_consistent_exports_witness() {
    use bitcoin_primitives::witness::error::{UnexpectedEofError as _, WitnessDecoderError as _};
    use bitcoin_primitives::witness::{
        Iter, UnexpectedEofError, Witness, WitnessDecoder, WitnessDecoderError, WitnessEncoder,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `witness_version` module.
#[test]
fn p_consistent_exports_witness_version() {
    use bitcoin_primitives::witness_version::error::{
        InvalidWitnessVersionError as _, ParseWitnessVersionError as _,
    };
    use bitcoin_primitives::witness_version::{
        InvalidWitnessVersionError, ParseWitnessVersionError, WitnessVersion,
    };
}
