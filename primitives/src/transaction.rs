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

#[cfg(feature = "alloc")]
use core::cmp;
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ArrayEncoder, BytesEncoder, CompactSizeEncoder, Encodable, Encoder2};
#[cfg(feature = "alloc")]
use encoding::{Encoder, Encoder3, Encoder6, SliceEncoder};
#[cfg(feature = "alloc")]
use hashes::sha256d;
#[cfg(feature = "alloc")]
use internals::compact_size;
#[cfg(feature = "hex")]
use internals::write_err;
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "hex")]
use units::parse_int;

#[cfg(feature = "alloc")]
use crate::amount::AmountEncoder;
#[cfg(feature = "alloc")]
use crate::locktime::absolute::LockTimeEncoder;
#[cfg(feature = "alloc")]
use crate::prelude::Vec;
#[cfg(feature = "alloc")]
use crate::script::ScriptEncoder;
#[cfg(feature = "alloc")]
use crate::sequence::SequenceEncoder;
#[cfg(feature = "alloc")]
use crate::witness::WitnessEncoder;
#[cfg(feature = "alloc")]
use crate::{absolute, Amount, ScriptPubKeyBuf, ScriptSigBuf, Sequence, Weight, Witness};

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(inline)]
pub use crate::hash_types::{Ntxid, Txid, Wtxid};

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
        let normalized = Transaction {
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
    fn from(tx: Transaction) -> Txid { tx.compute_txid() }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Txid {
    #[inline]
    fn from(tx: &Transaction) -> Txid { tx.compute_txid() }
}

#[cfg(feature = "alloc")]
impl From<Transaction> for Wtxid {
    #[inline]
    fn from(tx: Transaction) -> Wtxid { tx.compute_wtxid() }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Wtxid {
    #[inline]
    fn from(tx: &Transaction) -> Wtxid { tx.compute_wtxid() }
}

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
    enc.input(compact_size::encode(input_len).as_slice());
    for input in &tx.inputs {
        // Encode each input same as we do in `Encodable for TxIn`.
        enc.input(input.previous_output.txid.as_byte_array());
        enc.input(&input.previous_output.vout.to_le_bytes());

        let script_sig_bytes = input.script_sig.as_bytes();
        enc.input(compact_size::encode(script_sig_bytes.len()).as_slice());
        enc.input(script_sig_bytes);

        enc.input(&input.sequence.0.to_le_bytes());
    }

    // Encode outputs with leading compact size encoded int.
    let output_len = tx.outputs.len();
    enc.input(compact_size::encode(output_len).as_slice());
    for output in &tx.outputs {
        // Encode each output same as we do in `Encodable for TxOut`.
        enc.input(&output.amount.to_sat().to_le_bytes());

        let script_pubkey_bytes = output.script_pubkey.as_bytes();
        enc.input(compact_size::encode(script_pubkey_bytes.len()).as_slice());
        enc.input(script_pubkey_bytes);
    }

    if uses_segwit_serialization {
        // BIP-0141 (SegWit) transaction serialization also includes the witness data.
        for input in &tx.inputs {
            // Same as `Encodable for Witness`.
            enc.input(compact_size::encode(input.witness.len()).as_slice());
            for element in &input.witness {
                enc.input(compact_size::encode(element.len()).as_slice());
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
            CompactSizeEncoder::new(self.inputs.len() as u64),
            SliceEncoder::new(self.inputs.as_ref()),
        );
        let outputs = Encoder2::new(
            CompactSizeEncoder::new(self.outputs.len() as u64),
            SliceEncoder::new(self.outputs.as_ref()),
        );
        let lock_time = self.lock_time.encoder();

        if self.uses_segwit_serialization() {
            let segwit = ArrayEncoder::new([0x00, 0x01]);
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
    pub const EMPTY_COINBASE: TxIn = TxIn {
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
impl<'e> Encoder for WitnessesEncoder<'e> {
    #[inline]
    fn current_chunk(&self) -> Option<&[u8]> {
        // `advance` sets `cur_enc` to `None` once the slice encoder is completely exhausted.
        // `current_chunk` is required to return `None` if called after the encoder is exhausted.
        self.cur_enc.as_ref().and_then(WitnessEncoder::current_chunk)
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
                if cur.current_chunk().is_some() {
                    return true;
                }
            } else {
                self.cur_enc = None; // shortcut the next call to advance()
                return false;
            }
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
    /// The encoder for the [`TxOut`] type.
    pub struct OutPointEncoder<'e>(Encoder2<BytesEncoder<'e>, ArrayEncoder<4>>);
}

impl Encodable for OutPoint {
    type Encoder<'e>
        = OutPointEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        OutPointEncoder(Encoder2::new(
            BytesEncoder::new(self.txid.as_byte_array()),
            ArrayEncoder::new(self.vout.to_le_bytes()),
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
        Ok(OutPoint {
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

            impl<'de> de::Visitor<'de> for StringVisitor {
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
    Txid(hex::HexToArrayError),
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
    pub const fn maybe_non_standard(version: u32) -> Version { Self(version) }

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
        self.0 == Version::ONE.0 || self.0 == Version::TWO.0 || self.0 == Version::THREE.0
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
        VersionEncoder(encoding::ArrayEncoder::new(self.to_u32().to_le_bytes()))
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Transaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Transaction {
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
        Ok(TxIn {
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
        Ok(TxOut { amount: Amount::arbitrary(u)?, script_pubkey: ScriptPubKeyBuf::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for OutPoint {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(OutPoint { txid: Txid::arbitrary(u)?, vout: u32::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Version {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight the case of normal version numbers
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Version::ONE),
            1 => Ok(Version::TWO),
            2 => Ok(Version::THREE),
            _ => Ok(Version(u.arbitrary()?)),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::{format, vec};

    use encoding::Encoder as _;

    use super::*;
    #[cfg(all(feature = "alloc", feature = "hex"))]
    use crate::absolute::LockTime;

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
            inputs: vec![txin.clone()],
            outputs: vec![txout.clone()],
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
            Some(
                &[
                    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                    12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
                ][..]
            )
        );
        assert!(encoder.advance());

        // The vout
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 0, 0, 0][..]));
        assert!(!encoder.advance());

        // Exhausted
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_tx_out() {
        let out = tx_out();
        let mut encoder = out.encoder();

        // The amount.
        assert_eq!(encoder.current_chunk(), Some(&[1, 0, 0, 0, 0, 0, 0, 0][..]));
        assert!(encoder.advance());

        // The script pubkey length prefix.
        assert_eq!(encoder.current_chunk(), Some(&[3u8][..]));
        assert!(encoder.advance());

        // The script pubkey data.
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(!encoder.advance());

        // Exhausted
        assert_eq!(encoder.current_chunk(), None);
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
            Some(
                &[
                    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                    12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
                ][..]
            )
        );
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 0, 0, 0][..]));
        assert!(encoder.advance());

        // The script sig
        assert_eq!(encoder.current_chunk(), Some(&[3u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(encoder.advance());

        // The sequence
        assert_eq!(encoder.current_chunk(), Some(&[0xffu8, 0xff, 0xff, 0xff][..]));
        assert!(!encoder.advance());

        // Exhausted
        assert_eq!(encoder.current_chunk(), None);
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
        assert_eq!(encoder.current_chunk(), Some(&[2u8, 0, 0, 0][..]));
        assert!(encoder.advance());

        // The segwit marker and flag
        assert_eq!(encoder.current_chunk(), Some(&[0u8, 1][..]));
        assert!(encoder.advance());

        // The input (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), Some(&[1u8][..]));
        assert!(encoder.advance());
        assert_eq!(
            encoder.current_chunk(),
            Some(
                &[
                    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                    12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
                ][..]
            )
        );
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 0, 0, 0][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[3u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[0xffu8, 0xff, 0xff, 0xff][..]));
        assert!(encoder.advance());

        // The output (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), Some(&[1u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1, 0, 0, 0, 0, 0, 0, 0][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[3u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(encoder.advance());

        // The witness
        assert_eq!(encoder.current_chunk(), Some(&[1u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[3u8, 1, 2, 3][..]));
        assert!(encoder.advance());

        // The lock time.
        assert_eq!(encoder.current_chunk(), Some(&[0, 0, 0, 0][..]));
        assert!(!encoder.advance());

        // Exhausted
        assert_eq!(encoder.current_chunk(), None);
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
        assert_eq!(encoder.current_chunk(), Some(&[2u8, 0, 0, 0][..]));
        assert!(encoder.advance());

        // Advance past the optional segwit bytes encoder.
        assert!(encoder.advance());

        // The input (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), Some(&[1u8][..]));
        assert!(encoder.advance());
        assert_eq!(
            encoder.current_chunk(),
            Some(
                &[
                    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                    12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
                ][..]
            )
        );
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 0, 0, 0][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[3u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[0xffu8, 0xff, 0xff, 0xff][..]));
        assert!(encoder.advance());

        // The output (same as tested above) but with vec length prefix.
        assert_eq!(encoder.current_chunk(), Some(&[1u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1, 0, 0, 0, 0, 0, 0, 0][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[3u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(encoder.advance());

        // Advance past the optional witnesses encoder.
        assert!(encoder.advance());

        // The lock time.
        assert_eq!(encoder.current_chunk(), Some(&[0, 0, 0, 0][..]));
        assert!(!encoder.advance());

        // Exhausted
        assert_eq!(encoder.current_chunk(), None);
    }
}
