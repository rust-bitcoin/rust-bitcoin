// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `primitives`.
//!
//! The point of these tests is to check the API surface as opposed to test the API functionality.
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
use bitcoin_primitives::script::{
    self, Builder, PushBytes, PushBytesBuf, RedeemScriptTag, ScriptHash, ScriptPubKeyBufDecoder,
    ScriptPubKeyTag, ScriptSigBufDecoder, ScriptSigTag, SignetBlockScriptTag, TapScriptTag,
    WScriptHash, WitnessScriptTag,
};
use bitcoin_primitives::{
    absolute, block, merkle_tree, opcodes, pow, relative, transaction, witness, witness_version,
    OutPoint, RedeemScript, RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf, ScriptSig,
    ScriptSigBuf, Sequence, SignetBlockScript, SignetBlockScriptBuf, TapScript, TapScriptBuf,
    Transaction, TxIn, TxOut, Txid, Witness, WitnessScript, WitnessScriptBuf, Wtxid,
};
use hashes::sha256t;

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: block::Checked, // Empty enums are not constructable.
    b: block::Unchecked,
    c: absolute::LockTime,
    d: relative::LockTime,
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
    i1: pow::CompactTarget,
    i2: pow::Target,
    i3: pow::Work,
    j1: &'a RedeemScript,
    j2: &'a ScriptPubKey,
    j3: &'a ScriptSig,
    j4: &'a SignetBlockScript,
    j5: &'a TapScript,
    j6: &'a WitnessScript,
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: SignetBlockScriptBuf,
    m5: TapScriptBuf,
    m6: WitnessScriptBuf,
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
    i1: pow::CompactTarget,
    i2: pow::Target,
    i3: pow::Work,
    // j: &'a Script,
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: SignetBlockScriptBuf,
    m5: TapScriptBuf,
    m6: WitnessScriptBuf,
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
    y: Builder<ScriptSigTag>,
    z: PushBytesBuf,
    aa: opcodes::Opcode,
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
    i1: pow::CompactTarget,
    i2: pow::Target,
    i3: pow::Work,
    // j: &'a Script,
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: SignetBlockScriptBuf,
    m5: TapScriptBuf,
    m6: WitnessScriptBuf,
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
    y: Builder<ScriptSigTag>,
    z: PushBytesBuf,
    aa: opcodes::Opcode,
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
    i1: pow::CompactTarget,
    i2: pow::Target,
    i3: pow::Work,
    // j: &'a Script,  // Doesn't implement `Clone`.
    k: ScriptHash,
    l: WScriptHash,
    m1: RedeemScriptBuf,
    m2: ScriptPubKeyBuf,
    m3: ScriptSigBuf,
    m4: SignetBlockScriptBuf,
    m5: TapScriptBuf,
    m6: WitnessScriptBuf,
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
    // y: Builder<ScriptSigTag>, // Doesn't implement `Ord` or `Hash`.
    z: PushBytesBuf,
    // aa: opcodes::Opcode, // Deliberately does not implement `Ord` (see type docs).
}

/// A struct that includes all types that implement `Default`.
#[derive(Default, Debug, PartialEq, Eq)] // C-COMMON-TRAITS: `Default` (others just so we can test).
struct Default {
    a: block::Version,
    b1: &'static RedeemScript,
    b2: &'static ScriptPubKey,
    b3: &'static ScriptSig,
    b4: &'static SignetBlockScript,
    b5: &'static TapScript,
    b6: &'static WitnessScript,
    c1: RedeemScriptBuf,
    c2: ScriptPubKeyBuf,
    c3: ScriptSigBuf,
    c4: SignetBlockScriptBuf,
    c5: TapScriptBuf,
    c6: WitnessScriptBuf,
    d: Sequence,
    e: Witness,
    f: Builder<ScriptSigTag>,
    g: PushBytesBuf,
}

/// A struct that includes all public decoder types.
#[derive(Default)] // All decoders implement `Default`.
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
    h: script::PushBytesError,
    i: script::ScriptBufDecoderError,
    j: block::BlockDecoderError,
    k: block::HeaderDecoderError,
    l: block::VersionDecoderError,
    m: block::InvalidBlockError,
    n: block::BlockHashDecoderError,
    o: block::BlockHeightDecoderError,
    p: block::TooBigForRelativeHeightError,
    q: merkle_tree::TxMerkleNodeDecoderError,
    r: transaction::TransactionDecoderError,
    s: transaction::TxInDecoderError,
    t: transaction::TxOutDecoderError,
    u: transaction::OutPointDecoderError,
    v: transaction::VersionDecoderError,
    w: witness::WitnessDecoderError,
    x: witness::UnexpectedEofError,
    y: witness_version::ParseWitnessVersionError,
    z: witness_version::InvalidWitnessVersionError,
}

#[test]
fn api_can_use_units_modules_from_crate_root() {
    use bitcoin_primitives::{amount, block, fee_rate, locktime, weight};
}

#[test]
fn api_can_use_units_types_from_crate_root() {
    use bitcoin_primitives::{
        Amount, BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate,
        NumOpResult, Sequence, SignedAmount, Weight,
    };
}

#[test]
fn api_can_use_all_units_types_from_module_amount() {
    use bitcoin_primitives::amount::{
        Amount, Denomination, Display, OutOfRangeError, ParseAmountError, ParseDenominationError,
        ParseError, SignedAmount,
    };
}

#[test]
fn api_can_use_all_units_types_from_module_amount_error() {
    use bitcoin_primitives::amount::error::{
        InputTooLargeError, InvalidCharacterError, MissingDenominationError, MissingDigitsError,
        OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError,
        PossiblyConfusingDenominationError, TooPreciseError, UnknownDenominationError,
    };
}

#[test]
fn api_can_use_all_units_types_from_module_pow() {
    use bitcoin_primitives::pow::{CompactTarget, CompactTargetDecoderError, Target, Work};
}

#[test]
fn api_can_use_modules_from_crate_root() {
    use bitcoin_primitives::{
        amount, block, fee_rate, locktime, merkle_tree, opcodes, parse_int, pow, result, script,
        sequence, time, transaction, weight, witness, witness_version,
    };
}

#[test]
fn api_can_use_types_from_crate_root() {
    use bitcoin_primitives::{
        Block, BlockChecked, BlockHash, BlockHeader, BlockUnchecked, BlockValidation, BlockVersion,
        CompactTarget, OutPoint, RedeemScript, RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf,
        ScriptSig, ScriptSigBuf, Sequence, SignetBlockScript, SignetBlockScriptBuf, TapScript,
        TapScriptBuf, Target, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
        WitnessCommitment, WitnessScript, WitnessScriptBuf, Work, Wtxid,
    };
}

#[test]
fn api_can_use_all_types_from_module_locktime() {
    use bitcoin_primitives::locktime::relative::error::{
        DisabledLockTimeError, InvalidHeightError, InvalidTimeError,
    };
    use bitcoin_primitives::locktime::relative::LockTime;
    use bitcoin_primitives::locktime::{absolute, relative};
}

#[test]
fn api_can_use_all_types_from_module_script() {
    // Aliased with `_` because the same types are imported from `script` below.
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
        MAX_REDEEM_SCRIPT_SIZE, MAX_WITNESS_SCRIPT_SIZE,
    };
}

#[test]
fn api_can_use_all_types_from_module_block() {
    // Aliased with `_` because the same types are imported from `block` below.
    use bitcoin_primitives::block::error::{
        BlockHashDecoderError as _, BlockHeightDecoderError as _, TooBigForRelativeHeightError as _,
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

#[test]
fn api_can_use_all_types_from_module_merkle_tree() {
    use bitcoin_primitives::merkle_tree::{
        TxMerkleNode, TxMerkleNodeDecoder, TxMerkleNodeDecoderError, TxMerkleNodeEncoder,
        WitnessMerkleNode,
    };
}

#[test]
fn api_can_use_all_types_from_module_opcodes() {
    use bitcoin_primitives::opcodes::all::*;
    use bitcoin_primitives::opcodes::{all, Opcode};
}

#[test]
fn api_can_use_all_types_from_module_transaction() {
    use bitcoin_primitives::transaction::{
        BlockHashDecoder, BlockHashDecoderError, Ntxid, OutPoint, OutPointDecoder,
        OutPointDecoderError, OutPointEncoder, ParseOutPointError, Transaction, TransactionDecoder,
        TransactionDecoderError, TransactionEncoder, TxIn, TxInDecoder, TxInDecoderError,
        TxInEncoder, TxOut, TxOutDecoder, TxOutDecoderError, TxOutEncoder, Txid, Version,
        VersionDecoder, VersionDecoderError, VersionEncoder, Wtxid,
    };
}

#[test]
fn api_can_use_all_types_from_module_witness() {
    use bitcoin_primitives::witness::{
        Iter, UnexpectedEofError, Witness, WitnessDecoder, WitnessDecoderError, WitnessEncoder,
    };
}

#[test]
fn api_can_use_all_types_from_module_witness_version() {
    use bitcoin_primitives::witness_version::error::{ParseWitnessVersionError, InvalidWitnessVersionError};
    use bitcoin_primitives::witness_version::WitnessVersion;
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
        relative::LockTime::ZERO;
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
        pow::CompactTarget::arbitrary(&mut u).unwrap();
        pow::Target::MAX;
        pow::Target::MAX.to_work();
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
        Witness::arbitrary(&mut u).unwrap().iter();
        Builder::<ScriptSigTag>::new();
        PUSH_BYTES.as_push_bytes();
        PUSH_BYTES.clone();
        opcodes::Opcode::from_u8(0x51);
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
        b1: RedeemScript::from_bytes(&[]),
        b2: ScriptPubKey::from_bytes(&[]),
        b3: ScriptSig::from_bytes(&[]),
        b4: SignetBlockScript::from_bytes(&[]),
        b5: TapScript::from_bytes(&[]),
        b6: WitnessScript::from_bytes(&[]),
        c1: RedeemScriptBuf::from_bytes(Vec::new()),
        c2: ScriptPubKeyBuf::from_bytes(Vec::new()),
        c3: ScriptSigBuf::from_bytes(Vec::new()),
        c4: SignetBlockScriptBuf::from_bytes(Vec::new()),
        c5: TapScriptBuf::from_bytes(Vec::new()),
        c6: WitnessScriptBuf::from_bytes(Vec::new()),
        d: Sequence::MAX,
        e: Witness::new(),
        f: Builder::new(),
        g: PushBytesBuf::new(),
    };
    assert_eq!(got, want);
}

#[test]
fn decoders_implement_default() { let _ = Decoders::default(); }

#[test]
fn decoders_implement_new() {
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

#[test]
// The traits in this crate are `block::Validation`, `script::Tag`, `script::ScriptHashableTag`,
// and `script::PushBytesErrorReport`. `block::Validation` is not dyn compatible.
fn dyn_compatible() {
    struct DynCompatible<'a> {
        a: Box<dyn script::Tag>,
        b: Box<dyn script::ScriptHashableTag>,
        c: &'a dyn script::PushBytesErrorReport,
    }
}
