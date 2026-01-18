// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.

use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "alloc")]
use core::{cmp, mem};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ArrayEncoder, BytesEncoder, Encodable, Encoder2, UnexpectedEofError};
#[cfg(feature = "alloc")]
use encoding::{
    CompactSizeEncoder, Decodable, Decoder, Decoder2, Decoder3, Encoder, Encoder3, Encoder6,
    SliceEncoder, VecDecoder, VecDecoderError,
};
#[cfg(feature = "alloc")]
use hashes::sha256d;
use internals::array::ArrayExt as _;
use internals::write_err;
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
#[cfg(all(feature = "hex", feature = "alloc"))]
use units::parse_int;

#[cfg(feature = "alloc")]
use crate::amount::{AmountDecoder, AmountEncoder};
#[cfg(feature = "alloc")]
use crate::locktime::absolute::{LockTimeDecoder, LockTimeDecoderError, LockTimeEncoder};
#[cfg(feature = "alloc")]
use crate::prelude::Vec;
#[cfg(feature = "alloc")]
use crate::script::{ScriptEncoder, ScriptPubKeyBufDecoder, ScriptSigBufDecoder};
#[cfg(feature = "alloc")]
use crate::sequence::{SequenceDecoder, SequenceEncoder};
#[cfg(feature = "alloc")]
use crate::witness::{WitnessDecoder, WitnessDecoderError, WitnessEncoder};
#[cfg(feature = "alloc")]
use crate::{absolute, Amount, ScriptPubKeyBuf, ScriptSigBuf, Sequence, Weight, Witness};

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(inline)]
pub use crate::hash_types::{Ntxid, Txid, Wtxid, BlockHashDecoder, BlockHashDecoderError, TxMerkleNodeDecoder, TxMerkleNodeDecoderError};

/// Bitcoin transaction.
///
/// An authenticated movement of coins.
///
/// See [Bitcoin Wiki: Transaction][wiki-transaction] for more information.
///
/// [wiki-transaction]: https://en.bitcoin.it/wiki/Transaction
///
/// # Bitcoin Core References
///
/// * [CTransaction definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L279)
///
/// # Serialization notes
///
/// If any inputs have nonempty witnesses, the entire transaction is serialized
/// in the post-BIP-0141 SegWit format which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized in the pre-BIP-0141
/// format.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if the transaction has no inputs, it is serialized in the BIP-0141 style. Be
/// aware that this differs from the transaction format in PSBT, which _never_
/// uses BIP-0141. (Ordinarily there is no conflict, since in PSBT transactions
/// are always unsigned and therefore their inputs have empty witnesses.)
///
/// The specific ambiguity is that SegWit uses the flag bytes `0001` where an old
/// serializer would read the number of transaction inputs. The old serializer
/// would interpret this as "no inputs, one output", which means the transaction
/// is invalid, and simply reject it. SegWit further specifies that this encoding
/// should *only* be used when some input has a nonempty witness; that is,
/// witness-less transactions should be encoded in the traditional format.
///
/// However, in protocols where transactions may legitimately have 0 inputs, e.g.
/// when parties are cooperatively funding a transaction, the "00 means SegWit"
/// heuristic does not work. Since SegWit requires such a transaction to be encoded
/// in the original transaction format (since it has no inputs and therefore
/// no input witnesses), a traditionally encoded transaction may have the `0001`
/// SegWit flag in it, which confuses most SegWit parsers including the one in
/// Bitcoin Core.
///
/// We therefore deviate from the spec by always using the SegWit witness encoding
/// for 0-input transactions, which results in unambiguously parseable transactions.
///
/// # A note on ordering
///
/// This type implements `Ord`, even though it contains a locktime, which is not
/// itself `Ord`. This was done to simplify applications that may need to hold
/// transactions inside a sorted container. We have ordered the locktimes based
/// on their representation as a `u32`, which is not a semantically meaningful
/// order, and therefore the ordering on `Transaction` itself is not semantically
/// meaningful either.
///
/// The ordering is, however, consistent with the ordering present in this library
/// before this change, so users should not notice any breakage (here) when
/// transitioning from 0.29 to 0.30.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[cfg(feature = "alloc")]
pub struct Transaction {
    /// The protocol version, is currently expected to be 1, 2 (BIP-0068) or 3 (BIP-0431).
    pub version: Version,
    /// Block height or timestamp. Transaction cannot be included in a block until this height/time.
    ///
    /// # Relevant BIPs
    ///
    /// * [BIP-0065 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
    /// * [BIP-0113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
    pub lock_time: absolute::LockTime,
    /// List of transaction inputs.
    pub inputs: Vec<TxIn>,
    /// List of transaction outputs.
    pub outputs: Vec<TxOut>,
}

#[cfg(feature = "alloc")]
impl Transaction {
    // https://github.com/bitcoin/bitcoin/blob/44b05bf3fef2468783dcebf651654fdd30717e7e/src/policy/policy.h#L27
    /// Maximum transaction weight for Bitcoin Core 25.0.
    pub const MAX_STANDARD_WEIGHT: Weight = Weight::from_wu(400_000);

    /// Computes a "normalized TXID" which does not include any signatures.
    ///
    /// This function is needed only for legacy (pre-Segwit or P2SH-wrapped segwit version 0)
    /// applications. This method clears the `script_sig` field of each input, which in Segwit
    /// transactions is already empty, so for Segwit transactions the ntxid will be equal to the
    /// txid, and you should simply use the latter.
    ///
    /// This gives a way to identify a transaction that is "the same" as another in the sense of
    /// having the same inputs and outputs.
    #[doc(alias = "ntxid")]
    pub fn compute_ntxid(&self) -> Ntxid {
        let normalized = Self {
            version: self.version,
            lock_time: self.lock_time,
            inputs: self
                .inputs
                .iter()
                .map(|txin| TxIn {
                    script_sig: ScriptSigBuf::new(),
                    witness: Witness::default(),
                    ..*txin
                })
                .collect(),
            outputs: self.outputs.clone(),
        };
        Ntxid::from_byte_array(normalized.compute_txid().to_byte_array())
    }

    /// Computes the [`Txid`].
    ///
    /// Hashes the transaction **excluding** the SegWit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-SegWit transactions which do not have any SegWit data,
    /// this will be equal to [`Transaction::compute_wtxid()`].
    #[doc(alias = "txid")]
    #[inline]
    pub fn compute_txid(&self) -> Txid {
        let hash = hash_transaction(self, false);
        Txid::from_byte_array(hash.to_byte_array())
    }

    /// Computes the SegWit version of the transaction id.
    ///
    /// Hashes the transaction **including** all SegWit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-SegWit transactions which do not have any SegWit data,
    /// this will be equal to [`Transaction::compute_txid()`].
    #[doc(alias = "wtxid")]
    #[inline]
    pub fn compute_wtxid(&self) -> Wtxid {
        let hash = hash_transaction(self, self.uses_segwit_serialization());
        Wtxid::from_byte_array(hash.to_byte_array())
    }

    /// Returns whether or not to serialize transaction as specified in BIP-0144.
    // This is duplicated in `bitcoin`, if you change it please do so in both places.
    #[inline]
    fn uses_segwit_serialization(&self) -> bool {
        if self.inputs.iter().any(|input| !input.witness.is_empty()) {
            return true;
        }
        // To avoid serialization ambiguity, no inputs means we use BIP-0141 serialization (see
        // `Transaction` docs for full explanation).
        self.inputs.is_empty()
    }

    /// Checks if this is a coinbase transaction.
    ///
    /// The first transaction in the block distributes the mining reward and is called the coinbase
    /// transaction. It is impossible to check if the transaction is first in the block, so this
    /// function checks the structure of the transaction instead - the previous output must be
    /// all-zeros (creates satoshis "out of thin air").
    #[doc(alias = "is_coin_base")] // method previously had this name
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output == OutPoint::COINBASE_PREVOUT
    }
}

#[cfg(feature = "alloc")]
impl cmp::PartialOrd for Transaction {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> { Some(self.cmp(other)) }
}

#[cfg(feature = "alloc")]
impl cmp::Ord for Transaction {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.version
            .cmp(&other.version)
            .then(self.lock_time.to_consensus_u32().cmp(&other.lock_time.to_consensus_u32()))
            .then(self.inputs.cmp(&other.inputs))
            .then(self.outputs.cmp(&other.outputs))
    }
}

#[cfg(feature = "alloc")]
impl From<Transaction> for Txid {
    #[inline]
    fn from(tx: Transaction) -> Self { tx.compute_txid() }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Txid {
    #[inline]
    fn from(tx: &Transaction) -> Self { tx.compute_txid() }
}

#[cfg(feature = "alloc")]
impl From<Transaction> for Wtxid {
    #[inline]
    fn from(tx: Transaction) -> Self { tx.compute_wtxid() }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Wtxid {
    #[inline]
    fn from(tx: &Transaction) -> Self { tx.compute_wtxid() }
}

/// Trait that abstracts over a transaction identifier i.e., `Txid` and `Wtxid`.
pub(crate) trait TxIdentifier: AsRef<[u8]> {}

impl TxIdentifier for Txid {}
impl TxIdentifier for Wtxid {}

// Duplicated in `bitcoin`.
/// The marker MUST be a 1-byte zero value: 0x00. (BIP-0141)
#[cfg(feature = "alloc")]
const SEGWIT_MARKER: u8 = 0x00;
/// The flag MUST be a 1-byte non-zero value. Currently, 0x01 MUST be used. (BIP-0141)
#[cfg(feature = "alloc")]
const SEGWIT_FLAG: u8 = 0x01;

// This is equivalent to consensus encoding but hashes the fields manually.
#[cfg(feature = "alloc")]
fn hash_transaction(tx: &Transaction, uses_segwit_serialization: bool) -> sha256d::Hash {
    use hashes::HashEngine as _;

    let mut enc = sha256d::Hash::engine();
    enc.input(&tx.version.0.to_le_bytes()); // Same as `encode::emit_i32`.

    if uses_segwit_serialization {
        // BIP-0141 (SegWit) transaction serialization also includes marker and flag.
        enc.input(&[SEGWIT_MARKER]);
        enc.input(&[SEGWIT_FLAG]);
    }

    // Encode inputs (excluding witness data) with leading compact size encoded int.
    let input_len = tx.inputs.len();
    enc.input(crate::compact_size_encode(input_len).as_slice());
    for input in &tx.inputs {
        // Encode each input same as we do in `Encodable for TxIn`.
        enc.input(input.previous_output.txid.as_byte_array());
        enc.input(&input.previous_output.vout.to_le_bytes());

        let script_sig_bytes = input.script_sig.as_bytes();
        enc.input(crate::compact_size_encode(script_sig_bytes.len()).as_slice());
        enc.input(script_sig_bytes);

        enc.input(&input.sequence.0.to_le_bytes());
    }

    // Encode outputs with leading compact size encoded int.
    let output_len = tx.outputs.len();
    enc.input(crate::compact_size_encode(output_len).as_slice());
    for output in &tx.outputs {
        // Encode each output same as we do in `Encodable for TxOut`.
        enc.input(&output.amount.to_sat().to_le_bytes());

        let script_pubkey_bytes = output.script_pubkey.as_bytes();
        enc.input(crate::compact_size_encode(script_pubkey_bytes.len()).as_slice());
        enc.input(script_pubkey_bytes);
    }

    if uses_segwit_serialization {
        // BIP-0141 (SegWit) transaction serialization also includes the witness data.
        for input in &tx.inputs {
            // Same as `Encodable for Witness`.
            enc.input(crate::compact_size_encode(input.witness.len()).as_slice());
            for element in &input.witness {
                enc.input(crate::compact_size_encode(element.len()).as_slice());
                enc.input(element);
            }
        }
    }

    // Same as `Encodable for absolute::LockTime`.
    enc.input(&tx.lock_time.to_consensus_u32().to_le_bytes());

    sha256d::Hash::from_engine(enc)
}

#[cfg(feature = "alloc")]
encoding::encoder_newtype! {
    /// The encoder for the [`Transaction`] type.
    pub struct TransactionEncoder<'e>(
        Encoder6<
            VersionEncoder,
        Option<ArrayEncoder<2>>,
        Encoder2<CompactSizeEncoder, SliceEncoder<'e, TxIn>>,
        Encoder2<CompactSizeEncoder, SliceEncoder<'e, TxOut>>,
        Option<WitnessesEncoder<'e>>,
        LockTimeEncoder,
        >
    );
}

#[cfg(feature = "alloc")]
impl Encodable for Transaction {
    type Encoder<'e>
        = TransactionEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        let version = self.version.encoder();
        let inputs = Encoder2::new(
            CompactSizeEncoder::new(self.inputs.len()),
            SliceEncoder::without_length_prefix(self.inputs.as_ref()),
        );
        let outputs = Encoder2::new(
            CompactSizeEncoder::new(self.outputs.len()),
            SliceEncoder::without_length_prefix(self.outputs.as_ref()),
        );
        let lock_time = self.lock_time.encoder();

        if self.uses_segwit_serialization() {
            let segwit = ArrayEncoder::without_length_prefix([0x00, 0x01]);
            let witnesses = WitnessesEncoder::new(self.inputs.as_slice());
            TransactionEncoder(Encoder6::new(
                version,
                Some(segwit),
                inputs,
                outputs,
                Some(witnesses),
                lock_time,
            ))
        } else {
            TransactionEncoder(Encoder6::new(version, None, inputs, outputs, None, lock_time))
        }
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl core::str::FromStr for Transaction {
    type Err = ParseTransactionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::hex_codec::HexPrimitive::from_str(s).map_err(ParseTransactionError)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&crate::hex_codec::HexPrimitive(self), f)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::LowerHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&crate::hex_codec::HexPrimitive(self), f)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::UpperHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&crate::hex_codec::HexPrimitive(self), f)
    }
}

/// An error that occurs during parsing of a [`Transaction`] from a hex string.
#[cfg(all(feature = "hex", feature = "alloc"))]
pub struct ParseTransactionError(crate::ParsePrimitiveError<Transaction>);

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::Debug for ParseTransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Debug::fmt(&self.0, f) }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::Display for ParseTransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Debug::fmt(&self, f) }
}

#[cfg(all(feature = "hex", feature = "alloc", feature = "std"))]
impl std::error::Error for ParseTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}

/// The decoder for the [`Transaction`] type.
#[cfg(feature = "alloc")]
pub struct TransactionDecoder {
    state: TransactionDecoderState,
}

#[cfg(feature = "alloc")]
impl TransactionDecoder {
    /// Constructs a new [`TransactionDecoder`].
    pub const fn new() -> Self {
        Self { state: TransactionDecoderState::Version(VersionDecoder::new()) }
    }
}

#[cfg(feature = "alloc")]
impl Default for TransactionDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "alloc")]
#[allow(clippy::too_many_lines)] // TODO: Can we clean this up?
impl Decoder for TransactionDecoder {
    type Output = Transaction;
    type Error = TransactionDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        use {
            TransactionDecoderError as E, TransactionDecoderErrorInner as Inner,
            TransactionDecoderState as State,
        };

        loop {
            // Attempt to push to the currently-active decoder and return early on success.
            match &mut self.state {
                State::Version(decoder) => {
                    if decoder.push_bytes(bytes)? {
                        // Still more bytes required.
                        return Ok(true);
                    }
                }
                State::Inputs(_, _, decoder) =>
                    if decoder.push_bytes(bytes)? {
                        return Ok(true);
                    },
                State::SegwitFlag(_) =>
                    if bytes.is_empty() {
                        return Ok(true);
                    },
                State::Outputs(_, _, _, decoder) =>
                    if decoder.push_bytes(bytes)? {
                        return Ok(true);
                    },
                State::Witnesses(_, _, _, _, decoder) =>
                    if decoder.push_bytes(bytes)? {
                        return Ok(true);
                    },
                State::LockTime(_, _, _, decoder) =>
                    if decoder.push_bytes(bytes)? {
                        return Ok(true);
                    },
                State::Done(..) => return Ok(false),
                State::Errored => panic!("call to push_bytes() after decoder errored"),
            }

            // If the above failed, end the current decoder and go to the next state.
            match mem::replace(&mut self.state, State::Errored) {
                State::Version(decoder) => {
                    let version = decoder.end()?;
                    self.state = State::Inputs(version, Attempt::First, VecDecoder::<TxIn>::new());
                }
                State::Inputs(version, attempt, decoder) => {
                    let inputs = decoder.end()?;

                    if Attempt::First == attempt {
                        if inputs.is_empty() {
                            self.state = State::SegwitFlag(version);
                        } else {
                            self.state = State::Outputs(
                                version,
                                inputs,
                                IsSegwit::No,
                                VecDecoder::<TxOut>::new(),
                            );
                        }
                    } else {
                        self.state = State::Outputs(
                            version,
                            inputs,
                            IsSegwit::Yes,
                            VecDecoder::<TxOut>::new(),
                        );
                    }
                }
                State::SegwitFlag(version) => {
                    let segwit_flag = bytes[0];
                    *bytes = &bytes[1..];

                    if segwit_flag != 1 {
                        return Err(E(Inner::UnsupportedSegwitFlag(segwit_flag)));
                    }
                    self.state = State::Inputs(version, Attempt::Second, VecDecoder::<TxIn>::new());
                }
                State::Outputs(version, inputs, is_segwit, decoder) => {
                    let outputs = decoder.end()?;
                    // Handle the zero-input case described in the `Transaction` docs.
                    if is_segwit == IsSegwit::Yes && !inputs.is_empty() {
                        self.state = State::Witnesses(
                            version,
                            inputs,
                            outputs,
                            Iteration(0),
                            WitnessDecoder::new(),
                        );
                    } else {
                        self.state =
                            State::LockTime(version, inputs, outputs, LockTimeDecoder::new());
                    }
                }
                State::Witnesses(version, mut inputs, outputs, iteration, decoder) => {
                    let iteration = iteration.0;

                    inputs[iteration].witness = decoder.end()?;
                    if iteration < inputs.len() - 1 {
                        self.state = State::Witnesses(
                            version,
                            inputs,
                            outputs,
                            Iteration(iteration + 1),
                            WitnessDecoder::new(),
                        );
                    } else {
                        if !inputs.is_empty() && inputs.iter().all(|input| input.witness.is_empty())
                        {
                            return Err(E(Inner::NoWitnesses));
                        }
                        self.state =
                            State::LockTime(version, inputs, outputs, LockTimeDecoder::new());
                    }
                }
                State::LockTime(version, inputs, outputs, decoder) => {
                    let lock_time = decoder.end()?;
                    self.state = State::Done(Transaction { version, lock_time, inputs, outputs });
                    return Ok(false);
                }
                State::Done(..) => return Ok(false),
                State::Errored => unreachable!("checked above"),
            }
        }
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        use {
            TransactionDecoderError as E, TransactionDecoderErrorInner as Inner,
            TransactionDecoderState as State,
        };

        match self.state {
            State::Version(_) => Err(E(Inner::EarlyEnd("version"))),
            State::Inputs(..) => Err(E(Inner::EarlyEnd("inputs"))),
            State::SegwitFlag(..) => Err(E(Inner::EarlyEnd("segwit flag"))),
            State::Outputs(..) => Err(E(Inner::EarlyEnd("outputs"))),
            State::Witnesses(..) => Err(E(Inner::EarlyEnd("witnesses"))),
            State::LockTime(..) => Err(E(Inner::EarlyEnd("locktime"))),
            State::Done(tx) => {
                // check for null prevout in non-coinbase txs
                if tx.inputs.len() > 1 {
                    for (index, input) in tx.inputs.iter().enumerate() {
                        if input.previous_output == OutPoint::COINBASE_PREVOUT {
                            return Err(E(Inner::NullPrevoutInNonCoinbase(index)));
                        }
                    }
                }
                // check coinbase scriptSig length (must be 2-100 bytes)
                if tx.is_coinbase() {
                    let len = tx.inputs[0].script_sig.len();
                    if len < 2 {
                        return Err(E(Inner::CoinbaseScriptSigTooSmall(len)));
                    }
                    if len > 100 {
                        return Err(E(Inner::CoinbaseScriptSigTooLarge(len)));
                    }
                }
                // check for duplicate inputs (CVE-2018-17144).
                let mut outpoints: Vec<_> = tx.inputs.iter().map(|i| i.previous_output).collect();
                outpoints.sort_unstable();
                for pair in outpoints.windows(2) {
                    if pair[0] == pair[1] {
                        return Err(E(Inner::DuplicateInput(pair[0])));
                    }
                }
                Ok(tx)
            }
            State::Errored => panic!("call to end() after decoder errored"),
        }
    }

    #[inline]
    fn read_limit(&self) -> usize {
        use TransactionDecoderState as State;

        match &self.state {
            State::Version(decoder) => decoder.read_limit(),
            State::Inputs(_, _, decoder) => decoder.read_limit(),
            State::SegwitFlag(_) => 1,
            State::Outputs(_, _, _, decoder) => decoder.read_limit(),
            State::Witnesses(_, _, _, _, decoder) => decoder.read_limit(),
            State::LockTime(_, _, _, decoder) => decoder.read_limit(),
            State::Done(_) => 0,
            // `read_limit` is not documented to panic or return an error, so we
            // return a dummy value if the decoder is in an error state.
            State::Errored => 0,
        }
    }
}

#[cfg(feature = "alloc")]
impl Decodable for Transaction {
    type Decoder = TransactionDecoder;
    fn decoder() -> Self::Decoder { TransactionDecoder::new() }
}

/// The state of the transiting decoder.
#[cfg(feature = "alloc")]
enum TransactionDecoderState {
    /// Decoding the transaction version.
    Version(VersionDecoder),
    /// Decoding the transaction inputs.
    Inputs(Version, Attempt, VecDecoder<TxIn>),
    /// Decoding the segwit flag.
    SegwitFlag(Version),
    /// Decoding the transaction outputs.
    Outputs(Version, Vec<TxIn>, IsSegwit, VecDecoder<TxOut>),
    /// Decoding the segwit transaction witnesses.
    Witnesses(Version, Vec<TxIn>, Vec<TxOut>, Iteration, WitnessDecoder),
    /// Decoding the transaction lock time.
    LockTime(Version, Vec<TxIn>, Vec<TxOut>, LockTimeDecoder),
    /// Done decoding the [`Transaction`].
    Done(Transaction),
    /// When `end()`ing a sub-decoder, encountered an error which prevented us
    /// from constructing the next sub-decoder.
    Errored,
}

/// Boolean used to track number of times we have attempted to decode the inputs vector.
#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Attempt {
    /// First time reading inputs.
    First,
    /// Second time reading inputs.
    Second,
}

/// Boolean used to track whether or not this transaction uses segwit encoding.
#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum IsSegwit {
    /// Yes so uses segwit encoding.
    Yes,
    /// No segwit flag, marker, or witnesses.
    No,
}

/// How many times we have state transitioned to encoding a witness (zero-based).
#[cfg(feature = "alloc")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct Iteration(usize);

/// An error consensus decoding a `Transaction`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDecoderError(TransactionDecoderErrorInner);

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum TransactionDecoderErrorInner {
    /// Error while decoding the `version`.
    Version(VersionDecoderError),
    /// We only support segwit flag value 0x01.
    UnsupportedSegwitFlag(u8),
    /// Error while decoding the `inputs`.
    Inputs(VecDecoderError<TxInDecoderError>),
    /// Error while decoding the `outputs`.
    Outputs(VecDecoderError<TxOutDecoderError>),
    /// Error while decoding one of the witnesses.
    Witness(WitnessDecoderError),
    /// Non-empty Segwit transaction with no witnesses.
    NoWitnesses,
    /// Error while decoding the `lock_time`.
    LockTime(LockTimeDecoderError),
    /// Attempt to call `end()` before the transaction was complete. Holds
    /// a description of the current state.
    EarlyEnd(&'static str),
    /// Null prevout in non-coinbase transaction.
    NullPrevoutInNonCoinbase(usize),
    /// Coinbase scriptSig too small (must be at least 2 bytes).
    CoinbaseScriptSigTooSmall(usize),
    /// Coinbase scriptSig is too large (must be at most 100 bytes).
    CoinbaseScriptSigTooLarge(usize),
    /// Transaction has duplicate inputs (this check prevents CVE-2018-17144 ).
    DuplicateInput(OutPoint),
}

#[cfg(feature = "alloc")]
impl From<Infallible> for TransactionDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl From<VersionDecoderError> for TransactionDecoderError {
    fn from(e: VersionDecoderError) -> Self { Self(TransactionDecoderErrorInner::Version(e)) }
}

#[cfg(feature = "alloc")]
impl From<VecDecoderError<TxInDecoderError>> for TransactionDecoderError {
    fn from(e: VecDecoderError<TxInDecoderError>) -> Self {
        Self(TransactionDecoderErrorInner::Inputs(e))
    }
}

#[cfg(feature = "alloc")]
impl From<VecDecoderError<TxOutDecoderError>> for TransactionDecoderError {
    fn from(e: VecDecoderError<TxOutDecoderError>) -> Self {
        Self(TransactionDecoderErrorInner::Outputs(e))
    }
}

#[cfg(feature = "alloc")]
impl From<WitnessDecoderError> for TransactionDecoderError {
    fn from(e: WitnessDecoderError) -> Self { Self(TransactionDecoderErrorInner::Witness(e)) }
}

#[cfg(feature = "alloc")]
impl From<LockTimeDecoderError> for TransactionDecoderError {
    fn from(e: LockTimeDecoderError) -> Self { Self(TransactionDecoderErrorInner::LockTime(e)) }
}

#[cfg(feature = "alloc")]
impl fmt::Display for TransactionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TransactionDecoderErrorInner as E;

        match self.0 {
            E::Version(ref e) => write_err!(f, "transaction decoder error"; e),
            E::UnsupportedSegwitFlag(v) => {
                write!(f, "we only support segwit flag value 0x01: {}", v)
            }
            E::Inputs(ref e) => write_err!(f, "transaction decoder error"; e),
            E::Outputs(ref e) => write_err!(f, "transaction decoder error"; e),
            E::Witness(ref e) => write_err!(f, "transaction decoder error"; e),
            E::NoWitnesses => write!(f, "non-empty Segwit transaction with no witnesses"),
            E::LockTime(ref e) => write_err!(f, "transaction decoder error"; e),
            E::EarlyEnd(s) => write!(f, "early end of transaction (still decoding {})", s),
            E::NullPrevoutInNonCoinbase(index) =>
                write!(f, "null prevout in non-coinbase transaction at input {}", index),
            E::CoinbaseScriptSigTooSmall(len) =>
                write!(f, "coinbase scriptSig too small: {} bytes (min 2)", len),
            E::CoinbaseScriptSigTooLarge(len) =>
                write!(f, "coinbase scriptSig too large: {} bytes (max 100)", len),
            E::DuplicateInput(ref outpoint) =>
                write!(f, "duplicate input: {:?}:{}", outpoint.txid, outpoint.vout),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "alloc")]
impl std::error::Error for TransactionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TransactionDecoderErrorInner as E;

        match self.0 {
            E::Version(ref e) => Some(e),
            E::UnsupportedSegwitFlag(_) => None,
            E::Inputs(ref e) => Some(e),
            E::Outputs(ref e) => Some(e),
            E::Witness(ref e) => Some(e),
            E::NoWitnesses => None,
            E::LockTime(ref e) => Some(e),
            E::EarlyEnd(_) => None,
            E::NullPrevoutInNonCoinbase(_) => None,
            E::CoinbaseScriptSigTooSmall(_) => None,
            E::CoinbaseScriptSigTooLarge(_) => None,
            E::DuplicateInput(_) => None,
        }
    }
}

/// Bitcoin transaction input.
///
/// It contains the location of the previous transaction's output,
/// that it spends and set of scripts that satisfy its spending
/// conditions.
///
/// # Bitcoin Core References
///
/// * [CTxIn definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L65)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg(feature = "alloc")]
pub struct TxIn {
    /// The reference to the previous output that is being used as an input.
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to be accepted.
    pub script_sig: ScriptSigBuf,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behavior cannot be enforced.
    pub sequence: Sequence,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the `TxIn` in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the `TxIn` in other
    /// (de)serialization routines.
    pub witness: Witness,
}

#[cfg(feature = "alloc")]
impl TxIn {
    /// An empty transaction input with the previous output as for a coinbase transaction.
    ///
    /// This has a 0-byte scriptSig which is **invalid** per consensus rules
    /// (coinbase scriptSig must be 2-100 bytes). This is kept for backwards compatibility
    /// in PSBT workflows where the scriptSig is filled in later.
    pub const EMPTY_COINBASE: Self = Self {
        previous_output: OutPoint::COINBASE_PREVOUT,
        script_sig: ScriptSigBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
}

#[cfg(feature = "alloc")]
encoding::encoder_newtype! {
    /// The encoder for the [`TxIn`] type.
    pub struct TxInEncoder<'e>(
        Encoder3<OutPointEncoder<'e>, ScriptEncoder<'e>, SequenceEncoder>
    );
}

#[cfg(feature = "alloc")]
impl Encodable for TxIn {
    type Encoder<'e>
        = Encoder3<OutPointEncoder<'e>, ScriptEncoder<'e>, SequenceEncoder>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder3::new(
            self.previous_output.encoder(),
            self.script_sig.encoder(),
            self.sequence.encoder(),
        )
    }
}

/// Encodes the witnesses from a list of inputs.
#[cfg(feature = "alloc")]
pub struct WitnessesEncoder<'e> {
    inputs: &'e [TxIn],
    /// Encoder for the current witness being encoded.
    cur_enc: Option<WitnessEncoder<'e>>,
}

#[cfg(feature = "alloc")]
impl<'e> WitnessesEncoder<'e> {
    /// Constructs a new encoder for all witnesses in a list of transaction inputs.
    pub fn new(inputs: &'e [TxIn]) -> Self {
        Self { inputs, cur_enc: inputs.first().map(|input| input.witness.encoder()) }
    }
}

#[cfg(feature = "alloc")]
impl Encoder for WitnessesEncoder<'_> {
    #[inline]
    fn current_chunk(&self) -> &[u8] {
        self.cur_enc.as_ref().map(WitnessEncoder::current_chunk).unwrap_or_default()
    }

    #[inline]
    fn advance(&mut self) -> bool {
        let Some(cur) = self.cur_enc.as_mut() else {
            return false;
        };

        loop {
            // On subsequent calls, attempt to advance the current encoder and return
            // success if this succeeds.
            if cur.advance() {
                return true;
            }
            // self.inputs guaranteed to be non-empty if cur_enc is non-None.
            self.inputs = &self.inputs[1..];

            // If advancing the current encoder failed, attempt to move to the next encoder.
            if let Some(input) = self.inputs.first() {
                *cur = input.witness.encoder();
                if !cur.current_chunk().is_empty() {
                    return true;
                }
            } else {
                self.cur_enc = None; // shortcut the next call to advance()
                return false;
            }
        }
    }
}

#[cfg(feature = "alloc")]
type TxInInnerDecoder = Decoder3<OutPointDecoder, ScriptSigBufDecoder, SequenceDecoder>;

/// The decoder for the [`TxIn`] type.
#[cfg(feature = "alloc")]
pub struct TxInDecoder(TxInInnerDecoder);

#[cfg(feature = "alloc")]
impl Decoder for TxInDecoder {
    type Output = TxIn;
    type Error = TxInDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(TxInDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (previous_output, script_sig, sequence) = self.0.end().map_err(TxInDecoderError)?;
        Ok(TxIn { previous_output, script_sig, sequence, witness: Witness::default() })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for TxIn {
    type Decoder = TxInDecoder;
    fn decoder() -> Self::Decoder {
        TxInDecoder(Decoder3::new(
            OutPointDecoder::new(),
            ScriptSigBufDecoder::new(),
            SequenceDecoder::new(),
        ))
    }
}

/// An error consensus decoding a `TxIn`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInDecoderError(<TxInInnerDecoder as Decoder>::Error);

#[cfg(feature = "alloc")]
impl From<Infallible> for TxInDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for TxInDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            encoding::Decoder3Error::First(ref e) => write_err!(f, "txin decoder error"; e),
            encoding::Decoder3Error::Second(ref e) => write_err!(f, "txin decoder error"; e),
            encoding::Decoder3Error::Third(ref e) => write_err!(f, "txin decoder error"; e),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "std")]
impl std::error::Error for TxInDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            encoding::Decoder3Error::First(ref e) => Some(e),
            encoding::Decoder3Error::Second(ref e) => Some(e),
            encoding::Decoder3Error::Third(ref e) => Some(e),
        }
    }
}

/// Bitcoin transaction output.
///
/// Defines new coins to be created as a result of the transaction,
/// along with spending conditions ("script", aka "output script"),
/// which an input spending it must satisfy.
///
/// An output that is not yet spent by an input is called Unspent Transaction Output ("UTXO").
///
/// # Bitcoin Core References
///
/// * [CTxOut definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L148)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg(feature = "alloc")]
pub struct TxOut {
    /// The value of the output.
    pub amount: Amount,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: ScriptPubKeyBuf,
}

#[cfg(feature = "alloc")]
encoding::encoder_newtype! {
    /// The encoder for the [`TxOut`] type.
    pub struct TxOutEncoder<'e>(Encoder2<AmountEncoder, ScriptEncoder<'e>>);
}

#[cfg(feature = "alloc")]
impl Encodable for TxOut {
    type Encoder<'e>
        = Encoder2<AmountEncoder, ScriptEncoder<'e>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(self.amount.encoder(), self.script_pubkey.encoder())
    }
}

#[cfg(feature = "alloc")]
type TxOutInnerDecoder = Decoder2<AmountDecoder, ScriptPubKeyBufDecoder>;

/// The decoder for the [`TxOut`] type.
#[cfg(feature = "alloc")]
pub struct TxOutDecoder(TxOutInnerDecoder);

#[cfg(feature = "alloc")]
impl Decoder for TxOutDecoder {
    type Output = TxOut;
    type Error = TxOutDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(TxOutDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (amount, script_pubkey) = self.0.end().map_err(TxOutDecoderError)?;
        Ok(TxOut { amount, script_pubkey })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for TxOut {
    type Decoder = TxOutDecoder;
    fn decoder() -> Self::Decoder {
        TxOutDecoder(Decoder2::new(AmountDecoder::new(), ScriptPubKeyBufDecoder::new()))
    }
}

/// An error consensus decoding a `TxOut`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutDecoderError(<TxOutInnerDecoder as Decoder>::Error);

#[cfg(feature = "alloc")]
impl From<Infallible> for TxOutDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for TxOutDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            encoding::Decoder2Error::First(ref e) => write_err!(f, "txout decoder error"; e),
            encoding::Decoder2Error::Second(ref e) => write_err!(f, "txout decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxOutDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            encoding::Decoder2Error::First(ref e) => Some(e),
            encoding::Decoder2Error::Second(ref e) => Some(e),
        }
    }
}

/// A reference to a transaction output.
///
/// # Bitcoin Core References
///
/// * [COutPoint definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L26)
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}

impl OutPoint {
    /// The number of bytes that an outpoint contributes to the size of a transaction.
    pub const SIZE: usize = 32 + 4; // The serialized lengths of txid and vout.

    /// The `OutPoint` used in a coinbase prevout.
    ///
    /// This is used as the dummy input for coinbase transactions because they don't have any
    /// previous outputs. In other words, does not point to a real transaction.
    pub const COINBASE_PREVOUT: Self = Self { txid: Txid::COINBASE_PREVOUT, vout: u32::MAX };
}

encoding::encoder_newtype! {
    /// The encoder for the [`OutPoint`] type.
    pub struct OutPointEncoder<'e>(Encoder2<BytesEncoder<'e>, ArrayEncoder<4>>);
}

impl Encodable for OutPoint {
    type Encoder<'e>
        = OutPointEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        OutPointEncoder(Encoder2::new(
            BytesEncoder::without_length_prefix(self.txid.as_byte_array()),
            ArrayEncoder::without_length_prefix(self.vout.to_le_bytes()),
        ))
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for OutPoint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl core::str::FromStr for OutPoint {
    type Err = ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 75 {
            // 64 + 1 + 10
            return Err(ParseOutPointError::TooLong);
        }
        let find = s.find(':');
        if find.is_none() || find != s.rfind(':') {
            return Err(ParseOutPointError::Format);
        }
        let colon = find.unwrap();
        if colon == 0 || colon == s.len() - 1 {
            return Err(ParseOutPointError::Format);
        }
        Ok(Self {
            txid: s[..colon].parse().map_err(ParseOutPointError::Txid)?,
            vout: parse_vout(&s[colon + 1..])?,
        })
    }
}

/// Parses a string-encoded transaction index (vout).
///
/// Does not permit leading zeroes or non-digit characters.
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    parse_int::int_from_str(s).map_err(ParseOutPointError::Vout)
}

/// The decoder for the [`OutPoint`] type.
// 32 for the txid + 4 for the vout
pub struct OutPointDecoder(encoding::ArrayDecoder<36>);

impl OutPointDecoder {
    /// Constructs a new [`OutPoint`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for OutPointDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for OutPointDecoder {
    type Output = OutPoint;
    type Error = OutPointDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(OutPointDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let encoded = self.0.end().map_err(OutPointDecoderError)?;
        let (txid_buf, vout_buf) = encoded.split_array::<32, 4>();

        let txid = Txid::from_byte_array(*txid_buf);
        let vout = u32::from_le_bytes(*vout_buf);

        Ok(OutPoint { txid, vout })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for OutPoint {
    type Decoder = OutPointDecoder;
    fn decoder() -> Self::Decoder { OutPointDecoder::default() }
}

/// Error while decoding an `OutPoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPointDecoderError(UnexpectedEofError);

impl core::fmt::Display for OutPointDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_err!(f, "out point decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutPointDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "serde")]
impl Serialize for OutPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&self)
        } else {
            use crate::serde::ser::SerializeStruct as _;

            let mut state = serializer.serialize_struct("OutPoint", 2)?;
            // serializing as an array was found in the past to break for some serializers so we use
            // a slice instead. This causes 8 bytes to be prepended for the length (even though this
            // is a bit silly because know the length).
            state.serialize_field("txid", self.txid.as_byte_array().as_slice())?;
            state.serialize_field("vout", &self.vout.to_le_bytes())?;
            state.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for OutPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct StringVisitor;

            impl de::Visitor<'_> for StringVisitor {
                type Value = OutPoint;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a string in format 'txid:vout'")
                }

                fn visit_str<E>(self, value: &str) -> Result<OutPoint, E>
                where
                    E: de::Error,
                {
                    value.parse::<OutPoint>().map_err(de::Error::custom)
                }
            }

            deserializer.deserialize_str(StringVisitor)
        } else {
            #[derive(Deserialize)]
            #[serde(field_identifier, rename_all = "lowercase")]
            enum Field {
                Txid,
                Vout,
            }

            struct OutPointVisitor;

            impl<'de> de::Visitor<'de> for OutPointVisitor {
                type Value = OutPoint;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("OutPoint struct with fields")
                }

                fn visit_seq<V>(self, mut seq: V) -> Result<OutPoint, V::Error>
                where
                    V: de::SeqAccess<'de>,
                {
                    let txid =
                        seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                    let vout =
                        seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    Ok(OutPoint { txid, vout })
                }

                fn visit_map<V>(self, mut map: V) -> Result<OutPoint, V::Error>
                where
                    V: de::MapAccess<'de>,
                {
                    let mut txid = None;
                    let mut vout = None;

                    while let Some(key) = map.next_key()? {
                        match key {
                            Field::Txid => {
                                if txid.is_some() {
                                    return Err(de::Error::duplicate_field("txid"));
                                }
                                let bytes: [u8; 32] = map.next_value()?;
                                txid = Some(Txid::from_byte_array(bytes));
                            }
                            Field::Vout => {
                                if vout.is_some() {
                                    return Err(de::Error::duplicate_field("vout"));
                                }
                                let bytes: [u8; 4] = map.next_value()?;
                                vout = Some(u32::from_le_bytes(bytes));
                            }
                        }
                    }

                    let txid = txid.ok_or_else(|| de::Error::missing_field("txid"))?;
                    let vout = vout.ok_or_else(|| de::Error::missing_field("vout"))?;

                    Ok(OutPoint { txid, vout })
                }
            }

            const FIELDS: &[&str] = &["txid", "vout"];
            deserializer.deserialize_struct("OutPoint", FIELDS, OutPointVisitor)
        }
    }
}

/// An error in parsing an [`OutPoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
pub enum ParseOutPointError {
    /// Error in TXID part.
    Txid(hex::DecodeFixedLengthBytesError),
    /// Error in vout part.
    Vout(parse_int::ParseIntError),
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl From<Infallible> for ParseOutPointError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl fmt::Display for ParseOutPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Txid(ref e) => write_err!(f, "error parsing TXID"; e),
            Self::Vout(ref e) => write_err!(f, "error parsing vout"; e),
            Self::Format => write!(f, "OutPoint not in <txid>:<vout> format"),
            Self::TooLong => write!(f, "vout should be at most 10 digits"),
            Self::VoutNotCanonical => write!(f, "no leading zeroes or + allowed in vout part"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "hex")]
impl std::error::Error for ParseOutPointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Txid(e) => Some(e),
            Self::Vout(e) => Some(e),
            Self::Format | Self::TooLong | Self::VoutNotCanonical => None,
        }
    }
}

/// The transaction version.
///
/// Currently, as specified by [BIP-0068] and [BIP-0431], version 1, 2, and 3 are considered standard.
///
/// Standardness of the inner `u32` is not an invariant because you are free to create transactions
/// of any version, transactions with non-standard version numbers will not be relayed by the
/// Bitcoin network.
///
/// [BIP-0068]: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
/// [BIP-0431]: https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(u32);

impl Version {
    /// The original Bitcoin transaction version (pre-BIP-0068).
    pub const ONE: Self = Self(1);

    /// The second Bitcoin transaction version (post-BIP-0068).
    pub const TWO: Self = Self(2);

    /// The third Bitcoin transaction version (post-BIP-0431).
    pub const THREE: Self = Self(3);

    /// Constructs a potentially non-standard transaction version.
    ///
    /// This can accept both standard and non-standard versions.
    #[inline]
    pub const fn maybe_non_standard(version: u32) -> Self { Self(version) }

    /// Returns the inner `u32` value of this `Version`.
    #[inline]
    pub const fn to_u32(self) -> u32 { self.0 }

    /// Returns true if this transaction version number is considered standard.
    ///
    /// The behavior of this method matches whatever Bitcoin Core considers standard at the time
    /// of the release and may change in future versions to accommodate new standard versions.
    /// As of Bitcoin Core 28.0 ([release notes](https://bitcoincore.org/en/releases/28.0/)),
    /// versions 1, 2, and 3 are considered standard.
    #[inline]
    pub const fn is_standard(self) -> bool {
        self.0 == Self::ONE.0 || self.0 == Self::TWO.0 || self.0 == Self::THREE.0
    }
}

impl fmt::Display for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl From<Version> for u32 {
    #[inline]
    fn from(version: Version) -> Self { version.0 }
}

encoding::encoder_newtype! {
    /// The encoder for the [`Version`] type.
    pub struct VersionEncoder(encoding::ArrayEncoder<4>);
}

impl encoding::Encodable for Version {
    type Encoder<'e> = VersionEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionEncoder(encoding::ArrayEncoder::without_length_prefix(self.to_u32().to_le_bytes()))
    }
}

/// The decoder for the [`Version`] type.
pub struct VersionDecoder(encoding::ArrayDecoder<4>);

impl VersionDecoder {
    /// Constructs a new [`Version`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for VersionDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for VersionDecoder {
    type Output = Version;
    type Error = VersionDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(VersionDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end().map_err(VersionDecoderError)?;
        let n = u32::from_le_bytes(bytes);
        Ok(Version::maybe_non_standard(n))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for Version {
    type Decoder = VersionDecoder;
    fn decoder() -> Self::Decoder { VersionDecoder(encoding::ArrayDecoder::<4>::new()) }
}

/// An error consensus decoding an `Version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDecoderError(encoding::UnexpectedEofError);

impl From<Infallible> for VersionDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for VersionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "version decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VersionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Transaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: Version::arbitrary(u)?,
            lock_time: absolute::LockTime::arbitrary(u)?,
            inputs: Vec::<TxIn>::arbitrary(u)?,
            outputs: Vec::<TxOut>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for TxIn {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            previous_output: OutPoint::arbitrary(u)?,
            script_sig: ScriptSigBuf::arbitrary(u)?,
            sequence: Sequence::arbitrary(u)?,
            witness: Witness::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for TxOut {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { amount: Amount::arbitrary(u)?, script_pubkey: ScriptPubKeyBuf::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for OutPoint {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { txid: Txid::arbitrary(u)?, vout: u32::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Version {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight the case of normal version numbers
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Self::ONE),
            1 => Ok(Self::TWO),
            2 => Ok(Self::THREE),
            _ => Ok(Self(u.arbitrary()?)),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    #[cfg(feature = "hex")]
    use alloc::string::ToString;
    use alloc::{format, vec};
    #[cfg(feature = "hex")]
    use core::str::FromStr as _;

    use encoding::Encoder as _;
    #[cfg(feature = "hex")]
    use hex_lit::hex;

    use super::*;
    #[cfg(all(feature = "alloc", feature = "hex"))]
    use crate::absolute::LockTime;

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn transaction_encode_decode_roundtrip() {
        // Create two different inputs to avoid duplicate input rejection
        let tx_in_1 = segwit_tx_in();
        let mut tx_in_2 = segwit_tx_in();
        tx_in_2.previous_output.vout = 2;

        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![tx_in_1, tx_in_2],
            outputs: vec![tx_out(), tx_out()],
        };

        let encoded = encoding::encode_to_vec(&tx);

        let mut decoder = Transaction::decoder();
        let mut slice = encoded.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let decoded = decoder.end().unwrap();

        assert_eq!(tx, decoded);
    }

    #[test]
    fn sanity_check() {
        let version = Version(123);
        assert_eq!(version.to_u32(), 123);
        assert_eq!(u32::from(version), 123);

        assert!(!version.is_standard());
        assert!(Version::ONE.is_standard());
        assert!(Version::TWO.is_standard());
        assert!(Version::THREE.is_standard());
    }

    #[test]
    fn transaction_functions() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xAA; 32]), // Arbitrary invalid dummy value.
                vout: 0,
            },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let txout = TxOut {
            amount: Amount::from_sat(123_456_789).unwrap(),
            script_pubkey: ScriptPubKeyBuf::new(),
        };

        let tx_orig = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_consensus(1_738_968_231), // The time this was written
            inputs: vec![txin],
            outputs: vec![txout],
        };

        // Test changing the transaction
        let mut tx = tx_orig.clone();
        tx.inputs[0].previous_output.txid = Txid::from_byte_array([0xFF; 32]);
        tx.outputs[0].amount = Amount::from_sat(987_654_321).unwrap();
        assert_eq!(tx.inputs[0].previous_output.txid.to_byte_array(), [0xFF; 32]);
        assert_eq!(tx.outputs[0].amount.to_sat(), 987_654_321);

        // Test uses_segwit_serialization
        assert!(!tx.uses_segwit_serialization());
        tx.inputs[0].witness.push(vec![0xAB, 0xCD, 0xEF]);
        assert!(tx.uses_segwit_serialization());

        // Test partial ord
        assert!(tx > tx_orig);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn transaction_hex_display() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xAA; 32]), // Arbitrary invalid dummy value.
                vout: 0,
            },
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let txout = TxOut {
            amount: Amount::from_sat(123_456_789).unwrap(),
            script_pubkey: ScriptPubKeyBuf::new(),
        };

        let tx_orig = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_consensus(1_765_112_030), // The time this was written
            inputs: vec![txin],
            outputs: vec![txout],
        };

        let encoded_tx = "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff0115cd5b070000000000de783569";
        let lower_hex_tx = format!("{:x}", tx_orig);
        let upper_hex_tx = format!("{:X}", tx_orig);

        // All of these should yield a lowercase hex
        assert_eq!(encoded_tx, lower_hex_tx);
        assert_eq!(encoded_tx, format!("{}", tx_orig));

        // And this should yield uppercase hex
        let upper_encoded = encoded_tx
            .chars()
            .map(|chr| chr.to_ascii_uppercase())
            .collect::<alloc::string::String>();
        assert_eq!(upper_encoded, upper_hex_tx);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn transaction_from_hex_str_round_trip() {
        // Create two different inputs to avoid duplicate input rejection
        let tx_in_1 = segwit_tx_in();
        let mut tx_in_2 = segwit_tx_in();
        tx_in_2.previous_output.vout = 2;

        // Create a transaction and convert it to a hex string
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![tx_in_1, tx_in_2],
            outputs: vec![tx_out(), tx_out()],
        };

        let lower_hex_tx = format!("{:x}", tx);
        let upper_hex_tx = format!("{:X}", tx);

        // Parse the hex strings back into transactions
        let parsed_lower = Transaction::from_str(&lower_hex_tx).unwrap();
        let parsed_upper = Transaction::from_str(&upper_hex_tx).unwrap();

        // The parsed transaction should match the originals
        assert_eq!(tx, parsed_lower);
        assert_eq!(tx, parsed_upper);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn transaction_from_hex_str_error() {
        use crate::ParsePrimitiveError;

        // OddLengthString error
        let odd = "abc"; // 3 chars, odd length
        let err = Transaction::from_str(odd).unwrap_err();
        assert!(matches!(err, ParseTransactionError(ParsePrimitiveError::OddLengthString(..))));

        // InvalidChar error
        let invalid = "zz";
        let err = Transaction::from_str(invalid).unwrap_err();
        assert!(matches!(err, ParseTransactionError(ParsePrimitiveError::InvalidChar(..))));

        // Decode error
        let bad = "deadbeef00"; // arbitrary even-length hex that will fail decoding
        let err = Transaction::from_str(bad).unwrap_err();
        assert!(matches!(err, ParseTransactionError(ParsePrimitiveError::Decode(..))));
    }

    #[test]
    #[cfg(feature = "hex")]
    fn outpoint_from_str() {
        // Check format errors
        let mut outpoint_str = "0".repeat(64); // No ":"
        let outpoint: Result<OutPoint, ParseOutPointError> = outpoint_str.parse();
        assert_eq!(outpoint, Err(ParseOutPointError::Format));

        outpoint_str.push(':'); // Empty vout
        let outpoint: Result<OutPoint, ParseOutPointError> = outpoint_str.parse();
        assert_eq!(outpoint, Err(ParseOutPointError::Format));

        outpoint_str.push('0'); // Correct format
        let outpoint: OutPoint = outpoint_str.parse().unwrap();
        assert_eq!(outpoint.txid, Txid::from_byte_array([0; 32]));
        assert_eq!(outpoint.vout, 0);

        // Check the number of bytes OutPoint contributes to the transaction is equal to SIZE
        let outpoint_size = outpoint.txid.as_byte_array().len() + outpoint.vout.to_le_bytes().len();
        assert_eq!(outpoint_size, OutPoint::SIZE);
    }

    #[test]
    #[cfg(feature = "hex")]
    fn outpoint_from_str_too_long() {
        // Check edge case: length exactly 75
        let mut outpoint_str = "0".repeat(64);
        outpoint_str.push_str(":1234567890");
        assert_eq!(outpoint_str.len(), 75);
        assert!(outpoint_str.parse::<OutPoint>().is_ok());

        // Check TooLong error (length 76)
        outpoint_str.push('0');
        assert_eq!(outpoint_str.len(), 76);
        let outpoint: Result<OutPoint, ParseOutPointError> = outpoint_str.parse();
        assert_eq!(outpoint, Err(ParseOutPointError::TooLong));
    }

    #[test]
    #[cfg(feature = "hex")]
    fn canonical_vout() {
        assert_eq!(parse_vout("0").unwrap(), 0);
        assert_eq!(parse_vout("1").unwrap(), 1);
        assert!(parse_vout("01").is_err()); // Leading zero not allowed
        assert!(parse_vout("+1").is_err()); // Non digits not allowed
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn outpoint_display_roundtrip() {
        let outpoint_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1";
        let outpoint: OutPoint = outpoint_str.parse().unwrap();
        assert_eq!(format!("{}", outpoint), outpoint_str);
    }

    #[test]
    fn version_display() {
        let version = Version(123);
        assert_eq!(format!("{}", version), "123");
    }

    // Creates an arbitrary dummy outpoint.
    #[cfg(any(feature = "hex", feature = "serde"))]
    fn tc_out_point() -> OutPoint {
        let s = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1";
        s.parse::<OutPoint>().unwrap()
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_deserialize_human_readable() {
        // `sered` serialization is the same as `Display` but includes quotes.
        let ser = "\"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1\"";
        let got = serde_json::from_str::<OutPoint>(ser).unwrap();
        let want = tc_out_point();

        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_deserialize_non_human_readable() {
        #[rustfmt::skip]
        let bytes = [
            // Length, prepended by the `serde` infrastructure because we use
            // slice serialization instead of array even though we know the length.
            32, 0, 0, 0, 0, 0, 0, 0,
            // The txid bytes
            32, 31, 30, 29, 28, 27, 26, 25,
            24, 23, 22, 21, 20, 19, 18, 17,
            16, 15, 14, 13, 12, 11, 10, 9,
            8, 7, 6, 5, 4, 3, 2, 1,
            // The vout
            1, 0, 0, 0
        ];

        let got = bincode::deserialize::<OutPoint>(&bytes).unwrap();
        let want = tc_out_point();

        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_human_readable_rountrips() {
        let out_point = tc_out_point();

        let ser = serde_json::to_string(&out_point).unwrap();
        let got = serde_json::from_str::<OutPoint>(&ser).unwrap();

        assert_eq!(got, out_point);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn out_point_serde_non_human_readable_rountrips() {
        let out_point = tc_out_point();

        let ser = bincode::serialize(&out_point).unwrap();
        let got = bincode::deserialize::<OutPoint>(&ser).unwrap();

        assert_eq!(got, out_point);
    }

    #[cfg(feature = "alloc")]
    fn tx_out() -> TxOut { TxOut { amount: Amount::ONE_SAT, script_pubkey: tc_script_pubkey() } }

    #[cfg(any(feature = "hex", feature = "serde"))]
    fn segwit_tx_in() -> TxIn {
        let bytes = [1u8, 2, 3];
        let data = [&bytes[..]];
        let witness = Witness::from_iter(data);

        TxIn {
            previous_output: tc_out_point(),
            script_sig: tc_script_sig(),
            sequence: Sequence::MAX,
            witness,
        }
    }

    #[cfg(feature = "alloc")]
    fn tc_script_pubkey() -> ScriptPubKeyBuf {
        let script_bytes = vec![1, 2, 3];
        ScriptPubKeyBuf::from_bytes(script_bytes)
    }

    #[cfg(any(feature = "hex", feature = "serde"))]
    fn tc_script_sig() -> ScriptSigBuf {
        let script_bytes = vec![1, 2, 3];
        ScriptSigBuf::from_bytes(script_bytes)
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn encode_out_point() {
        let out_point = tc_out_point();
        let mut encoder = out_point.encoder();

        // The txid
        assert_eq!(
            encoder.current_chunk(),
            &[
                32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
            ][..]
        );
        assert!(encoder.advance());

        // The vout
        assert_eq!(encoder.current_chunk(), &[1u8, 0, 0, 0][..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_tx_out() {
        let out = tx_out();
        let mut encoder = out.encoder();

        // The amount.
        assert_eq!(encoder.current_chunk(), &[1, 0, 0, 0, 0, 0, 0, 0][..]);
        assert!(encoder.advance());

        // The script pubkey length prefix.
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());

        // The script pubkey data.
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn encode_tx_in() {
        let txin = segwit_tx_in();
        let mut encoder = txin.encoder();

        // The outpoint (same as tested above).
        assert_eq!(
            encoder.current_chunk(),
            &[
                32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
            ][..]
        );
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 0, 0, 0][..]);
        assert!(encoder.advance());

        // The script sig
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(encoder.advance());

        // The sequence
        assert_eq!(encoder.current_chunk(), &[0xffu8, 0xff, 0xff, 0xff][..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn encode_segwit_transaction() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![segwit_tx_in()],
            outputs: vec![tx_out()],
        };

        let mut encoder = tx.encoder();

        // The version
        assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
        assert!(encoder.advance());

        // The segwit marker and flag
        assert_eq!(encoder.current_chunk(), &[0u8, 1][..]);
        assert!(encoder.advance());

        // The input (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(
            encoder.current_chunk(),
            &[
                32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
            ][..]
        );
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 0, 0, 0][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xffu8, 0xff, 0xff, 0xff][..]);
        assert!(encoder.advance());

        // The output (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1, 0, 0, 0, 0, 0, 0, 0][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(encoder.advance());

        // The witness
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8, 1, 2, 3][..]);
        assert!(encoder.advance());

        // The lock time.
        assert_eq!(encoder.current_chunk(), &[0, 0, 0, 0][..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn encode_non_segwit_transaction() {
        let mut tx_in = segwit_tx_in();
        tx_in.witness = Witness::default();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![tx_in],
            outputs: vec![tx_out()],
        };

        let mut encoder = tx.encoder();

        // The version
        assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
        assert!(encoder.advance());

        // Advance past the optional segwit bytes encoder.
        assert!(encoder.advance());

        // The input (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(
            encoder.current_chunk(),
            &[
                32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
            ][..]
        );
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 0, 0, 0][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xffu8, 0xff, 0xff, 0xff][..]);
        assert!(encoder.advance());

        // The output (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1, 0, 0, 0, 0, 0, 0, 0][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(encoder.advance());

        // Advance past the optional witnesses encoder.
        assert!(encoder.advance());

        // The lock time.
        assert_eq!(encoder.current_chunk(), &[0, 0, 0, 0][..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    // FIXME: Move all these encoding tests to a single file in `primitives/tests/`.
    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn encode_block() {
        use crate::{
            Block, BlockHash, BlockHeader, BlockTime, BlockVersion, CompactTarget, TxMerkleNode,
        };

        let seconds: u32 = 1_653_195_600; // Arbitrary timestamp: May 22nd, 5am UTC.

        let header = BlockHeader {
            version: BlockVersion::TWO,
            prev_blockhash: BlockHash::from_byte_array([0xab; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0xcd; 32]),
            time: BlockTime::from(seconds),
            bits: CompactTarget::from_consensus(0xbeef),
            nonce: 0xcafe,
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![segwit_tx_in()],
            outputs: vec![tx_out()],
        };

        let block = Block::new_unchecked(header, vec![tx]);
        let mut encoder = block.encoder();

        // The block header, 6 encoders, 1 chunk per encoder.

        // The block version.
        assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
        assert!(encoder.advance());
        // The previous block's blockhash.
        assert_eq!(
            encoder.current_chunk(),
            &[
                171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171,
                171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171
            ][..]
        );
        assert!(encoder.advance());
        // The merkle root hash.
        assert_eq!(
            encoder.current_chunk(),
            &[
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205
            ][..]
        );
        assert!(encoder.advance());
        // The block time.
        assert_eq!(encoder.current_chunk(), &[80, 195, 137, 98][..]);
        assert!(encoder.advance());
        // The target (bits).
        assert_eq!(encoder.current_chunk(), &[239, 190, 0, 0][..]);
        assert!(encoder.advance());
        // The nonce.
        assert_eq!(encoder.current_chunk(), &[254, 202, 0, 0][..]);
        assert!(encoder.advance());

        // The transaction list length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());

        // The transaction (same as tested above).

        // The version
        assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
        assert!(encoder.advance());
        // The segwit marker and flag
        assert_eq!(encoder.current_chunk(), &[0u8, 1][..]);
        assert!(encoder.advance());
        // The input (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(
            encoder.current_chunk(),
            &[
                32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
            ][..]
        );
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 0, 0, 0][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xffu8, 0xff, 0xff, 0xff][..]);
        assert!(encoder.advance());
        // The output (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1, 0, 0, 0, 0, 0, 0, 0][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(encoder.advance());
        // The witness
        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8, 1, 2, 3][..]);
        assert!(encoder.advance());
        // The lock time.
        assert_eq!(encoder.current_chunk(), &[0, 0, 0, 0][..]);
        assert!(!encoder.advance());

        // Exhausted
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn decode_segwit_transaction() {
        let tx_bytes = hex!(
            "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c01000000\
            00ffffffff01deb807000000000017a9140f3444e271620c736808aa7b33e370bd87cb5a078702483045022\
            100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd271\
            0e626347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c007176ed89410\
            55d3bcb8627d085e94553e62f057dcc00000000"
        );
        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().unwrap();

        // Attempt various truncations
        for i in [1, 10, 20, 50, 100, tx_bytes.len() / 2, tx_bytes.len()] {
            let mut decoder = Transaction::decoder();
            let mut slice = &tx_bytes[..tx_bytes.len() - i];
            // push_bytes will not fail because the data is not invalid, just truncated
            decoder.push_bytes(&mut slice).unwrap();
            // ...but end() will fail because we will be in some incomplete state
            decoder.end().unwrap_err();
        }

        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(tx.version, Version::TWO);
        assert_eq!(tx.inputs.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", tx.inputs[0].previous_output.txid),
            "7cac3cf9a112cf04901a51d605058615d56ffe6d04b45270e89d1720ea955859".to_string()
        );
        assert_eq!(tx.inputs[0].previous_output.vout, 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            format!("{:x}", tx.compute_txid()),
            "f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206".to_string()
        );
        assert_eq!(
            format!("{:x}", tx.compute_wtxid()),
            "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5".to_string()
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn decode_nonsegwit_transaction() {
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().unwrap();

        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(tx.version, Version::ONE);
        assert_eq!(tx.inputs.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", tx.inputs[0].previous_output.txid),
            "ce9ea9f6f5e422c6a9dbcddb3b9a14d1c78fab9ab520cb281aa2a74a09575da1".to_string()
        );
        assert_eq!(tx.inputs[0].previous_output.vout, 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            format!("{:x}", tx.compute_txid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(
            format!("{:x}", tx.compute_wtxid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn decode_segwit_without_witnesses_errors() {
        // A SegWit-serialized transaction with 1 input but no witnesses for any input.
        let tx_bytes = hex!(
            "02000000\
             0001\
             01\
             0000000000000000000000000000000000000000000000000000000000000000\
             00000000\
             00\
             ffffffff\
             01\
             0100000000000000\
             00\
             00\
             00000000"
        );

        let mut slice = tx_bytes.as_slice();
        let err = Transaction::decoder()
            .push_bytes(&mut slice)
            .expect_err("segwit tx with no witnesses should error");

        assert_eq!(err, TransactionDecoderError(TransactionDecoderErrorInner::NoWitnesses));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_zero_inputs() {
        // Test empty transaction with no inputs or outputs.
        let block: u32 = 741_521;
        let original_tx = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_height(block).expect("valid height"),
            inputs: vec![],
            outputs: vec![],
        };

        let encoded = encoding::encode_to_vec(&original_tx);
        let decoded_tx = encoding::decode_from_slice(&encoded).unwrap();

        assert_eq!(original_tx, decoded_tx);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_null_prevout_in_non_coinbase_transaction() {
        // Test vector taken from Bitcoin Core tx_invalid.json
        // https://github.com/bitcoin/bitcoin/blob/master/src/test/data/tx_invalid.json#L64
        // "Null txin, but without being a coinbase (because there are two inputs)"
        let tx_bytes = hex!("01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff00010000000000000000000000000000000000000000000000000000000000000000000000ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("null prevout in non-coinbase tx should be rejected");

        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::NullPrevoutInNonCoinbase(0))
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_coinbase_scriptsig_too_small() {
        // Test vector taken from Bitcoin Core tx_invalid.json
        // https://github.com/bitcoin/bitcoin/blob/master/src/test/data/tx_invalid.json#L57
        // "Coinbase of size 1"
        let tx_bytes = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0151ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("coinbase with 1-byte scriptSig should be rejected");

        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::CoinbaseScriptSigTooSmall(1))
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_coinbase_scriptsig_too_large() {
        // Test vector taken from Bitcoin Core tx_invalid.json:
        // https://github.com/bitcoin/bitcoin/blob/master/src/test/data/tx_invalid.json#L62
        // "Coinbase of size 101"
        let tx_bytes = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff655151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("coinbase with 101-byte scriptSig should be rejected");

        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::CoinbaseScriptSigTooLarge(101))
        );
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn accept_coinbase_scriptsig_min_valid() {
        // boundary test: 2 bytes is the minimum valid length
        let tx_bytes = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff025151ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().expect("coinbase with 2-byte scriptSig should be accepted");

        assert_eq!(tx.inputs[0].script_sig.len(), 2);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn accept_coinbase_scriptsig_max_valid() {
        // boundary test: 100 bytes is the maximum valid length
        let tx_bytes = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6451515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151ffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let tx = decoder.end().expect("coinbase with 100-byte scriptSig should be accepted");

        assert_eq!(tx.inputs[0].script_sig.len(), 100);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn reject_duplicate_inputs() {
        // Test vector from Bitcoin Core tx_invalid.json:
        // https://github.com/bitcoin/bitcoin/blob/master/src/test/data/tx_invalid.json#L50
        // Transaction has two inputs both spending the same outpoint
        let tx_bytes = hex!("01000000020001000000000000000000000000000000000000000000000000000000000000000000006c47304402204bb1197053d0d7799bf1b30cd503c44b58d6240cccbdc85b6fe76d087980208f02204beeed78200178ffc6c74237bb74b3f276bbb4098b5605d814304fe128bf1431012321039e8815e15952a7c3fada1905f8cf55419837133bd7756c0ef14fc8dfe50c0deaacffffffff0001000000000000000000000000000000000000000000000000000000000000000000006c47304402202306489afef52a6f62e90bf750bbcdf40c06f5c6b138286e6b6b86176bb9341802200dba98486ea68380f47ebb19a7df173b99e6bc9c681d6ccf3bde31465d1f16b3012321039e8815e15952a7c3fada1905f8cf55419837133bd7756c0ef14fc8dfe50c0deaacffffffff010000000000000000015100000000");

        let mut decoder = Transaction::decoder();
        let mut slice = tx_bytes.as_slice();
        decoder.push_bytes(&mut slice).unwrap();
        let err = decoder.end().expect_err("transaction with duplicate inputs should be rejected");

        let expected_outpoint = OutPoint {
            txid: Txid::from_byte_array([
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            vout: 0,
        };
        assert_eq!(
            err,
            TransactionDecoderError(TransactionDecoderErrorInner::DuplicateInput(
                expected_outpoint
            ))
        );
    }
}
