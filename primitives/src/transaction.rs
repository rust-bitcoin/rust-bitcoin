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
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
#[cfg(feature = "alloc")]
use internals::{compact_size, write_err};
#[cfg(feature = "alloc")]
use units::{parse, Amount, Weight};

#[cfg(feature = "alloc")]
use crate::locktime::absolute;
#[cfg(feature = "alloc")]
use crate::prelude::Vec;
#[cfg(feature = "alloc")]
use crate::script::ScriptBuf;
#[cfg(feature = "alloc")]
use crate::sequence::Sequence;
#[cfg(feature = "alloc")]
use crate::witness::Witness;

/// Bitcoin transaction.
///
/// An authenticated movement of coins.
///
/// See [Bitcoin Wiki: Transaction][wiki-transaction] for more information.
///
/// [wiki-transaction]: https://en.bitcoin.it/wiki/Transaction
///
/// ### Bitcoin Core References
///
/// * [CTtransaction definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L279)
///
/// ### Serialization notes
///
/// If any inputs have nonempty witnesses, the entire transaction is serialized
/// in the post-BIP141 SegWit format which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized in the pre-BIP141
/// format.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if the transaction has no inputs, it is serialized in the BIP141 style. Be
/// aware that this differs from the transaction format in PSBT, which _never_
/// uses BIP141. (Ordinarily there is no conflict, since in PSBT transactions
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
/// heuristic does not work. Since SegWit requires such a transaction be encoded
/// in the original transaction format (since it has no inputs and therefore
/// no input witnesses), a traditionally encoded transaction may have the `0001`
/// SegWit flag in it, which confuses most SegWit parsers including the one in
/// Bitcoin Core.
///
/// We therefore deviate from the spec by always using the SegWit witness encoding
/// for 0-input transactions, which results in unambiguously parseable transactions.
///
/// ### A note on ordering
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg(feature = "alloc")]
pub struct Transaction {
    /// The protocol version, is currently expected to be 1, 2 (BIP 68) or 3 (BIP 431).
    pub version: Version,
    /// Block height or timestamp. Transaction cannot be included in a block until this height/time.
    ///
    /// ### Relevant BIPs
    ///
    /// * [BIP-65 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
    /// * [BIP-113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
    pub lock_time: absolute::LockTime,
    /// List of transaction inputs.
    pub input: Vec<TxIn>,
    /// List of transaction outputs.
    pub output: Vec<TxOut>,
}

#[cfg(feature = "alloc")]
impl Transaction {
    // https://github.com/bitcoin/bitcoin/blob/44b05bf3fef2468783dcebf651654fdd30717e7e/src/policy/policy.h#L27
    /// Maximum transaction weight for Bitcoin Core 25.0.
    pub const MAX_STANDARD_WEIGHT: Weight = Weight::from_wu(400_000);

    /// Returns a reference to the transaction inputs.
    pub fn inputs(&self) -> &[TxIn] { &self.input }

    /// Returns a mutable reference to the transaction inputs.
    pub fn inputs_mut(&mut self) -> &mut [TxIn] { &mut self.input }

    /// Returns a reference to the transaction outputs.
    pub fn outputs(&self) -> &[TxOut] { &self.output }

    /// Returns a mutable reference to the transaction outputs.
    pub fn outputs_mut(&mut self) -> &mut [TxOut] { &mut self.output }

    /// Computes a "normalized TXID" which does not include any signatures.
    ///
    /// This gives a way to identify a transaction that is "the same" as
    /// another in the sense of having same inputs and outputs.
    #[doc(alias = "ntxid")]
    pub fn compute_ntxid(&self) -> sha256d::Hash {
        let cloned_tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self
                .input
                .iter()
                .map(|txin| TxIn {
                    script_sig: ScriptBuf::new(),
                    witness: Witness::default(),
                    ..*txin
                })
                .collect(),
            output: self.output.clone(),
        };
        cloned_tx.compute_txid().into()
    }

    /// Computes the [`Txid`].
    ///
    /// Hashes the transaction **excluding** the SegWit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-SegWit transactions which do not have any SegWit data,
    /// this will be equal to [`Transaction::compute_wtxid()`].
    #[doc(alias = "txid")]
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
    pub fn compute_wtxid(&self) -> Wtxid {
        let hash = hash_transaction(self, self.uses_segwit_serialization());
        Wtxid::from_byte_array(hash.to_byte_array())
    }

    /// Returns whether or not to serialize transaction as specified in BIP-144.
    // This is duplicated in `bitcoin`, if you change it please do so in both places.
    fn uses_segwit_serialization(&self) -> bool {
        if self.input.iter().any(|input| !input.witness.is_empty()) {
            return true;
        }
        // To avoid serialization ambiguity, no inputs means we use BIP141 serialization (see
        // `Transaction` docs for full explanation).
        self.input.is_empty()
    }
}

#[cfg(feature = "alloc")]
impl cmp::PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> { Some(self.cmp(other)) }
}

#[cfg(feature = "alloc")]
impl cmp::Ord for Transaction {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.version
            .cmp(&other.version)
            .then(self.lock_time.to_consensus_u32().cmp(&other.lock_time.to_consensus_u32()))
            .then(self.input.cmp(&other.input))
            .then(self.output.cmp(&other.output))
    }
}

#[cfg(feature = "alloc")]
impl From<Transaction> for Txid {
    fn from(tx: Transaction) -> Txid { tx.compute_txid() }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Txid {
    fn from(tx: &Transaction) -> Txid { tx.compute_txid() }
}

#[cfg(feature = "alloc")]
impl From<Transaction> for Wtxid {
    fn from(tx: Transaction) -> Wtxid { tx.compute_wtxid() }
}

#[cfg(feature = "alloc")]
impl From<&Transaction> for Wtxid {
    fn from(tx: &Transaction) -> Wtxid { tx.compute_wtxid() }
}

// Duplicated in `bitcoin`.
/// The marker MUST be a 1-byte zero value: 0x00. (BIP-141)
#[cfg(feature = "alloc")]
const SEGWIT_MARKER: u8 = 0x00;
/// The flag MUST be a 1-byte non-zero value. Currently, 0x01 MUST be used. (BIP-141)
#[cfg(feature = "alloc")]
const SEGWIT_FLAG: u8 = 0x01;

// This is equivalent to consensus encoding but hashes the fields manually.
#[cfg(feature = "alloc")]
fn hash_transaction(tx: &Transaction, uses_segwit_serialization: bool) -> sha256d::Hash {
    use hashes::HashEngine as _;

    let mut enc = sha256d::Hash::engine();
    enc.input(&tx.version.0.to_le_bytes()); // Same as `encode::emit_i32`.

    if uses_segwit_serialization {
        // BIP-141 (SegWit) transaction serialization also includes marker and flag.
        enc.input(&[SEGWIT_MARKER]);
        enc.input(&[SEGWIT_FLAG]);
    }

    // Encode inputs (excluding witness data) with leading compact size encoded int.
    let input_len = tx.input.len();
    enc.input(compact_size::encode(input_len).as_slice());
    for input in &tx.input {
        // Encode each input same as we do in `Encodable for TxIn`.
        enc.input(input.previous_output.txid.as_byte_array());
        enc.input(&input.previous_output.vout.to_le_bytes());

        let script_sig_bytes = input.script_sig.as_bytes();
        enc.input(compact_size::encode(script_sig_bytes.len()).as_slice());
        enc.input(script_sig_bytes);

        enc.input(&input.sequence.0.to_le_bytes())
    }

    // Encode outputs with leading compact size encoded int.
    let output_len = tx.output.len();
    enc.input(compact_size::encode(output_len).as_slice());
    for output in &tx.output {
        // Encode each output same as we do in `Encodable for TxOut`.
        enc.input(&output.value.to_sat().to_le_bytes());

        let script_pubkey_bytes = output.script_pubkey.as_bytes();
        enc.input(compact_size::encode(script_pubkey_bytes.len()).as_slice());
        enc.input(script_pubkey_bytes);
    }

    if uses_segwit_serialization {
        // BIP-141 (SegWit) transaction serialization also includes the witness data.
        for input in &tx.input {
            // Same as `Encodable for Witness`.
            enc.input(compact_size::encode(input.witness.len()).as_slice());
            for element in input.witness.iter() {
                enc.input(compact_size::encode(element.len()).as_slice());
                enc.input(element);
            }
        }
    }

    // Same as `Encodable for absolute::LockTime`.
    enc.input(&tx.lock_time.to_consensus_u32().to_le_bytes());

    sha256d::Hash::from_engine(enc)
}

/// Bitcoin transaction input.
///
/// It contains the location of the previous transaction's output,
/// that it spends and set of scripts that satisfy its spending
/// conditions.
///
/// ### Bitcoin Core References
///
/// * [CTxIn definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L65)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg(feature = "alloc")]
pub struct TxIn {
    /// The reference to the previous output that is being used as an input.
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to be accepted.
    pub script_sig: ScriptBuf,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behavior cannot be enforced.
    pub sequence: Sequence,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    pub witness: Witness,
}

#[cfg(feature = "alloc")]
impl TxIn {
    /// An empty transaction input with the previous output as for a coinbase transaction.
    pub const EMPTY_COINBASE: TxIn = TxIn {
        previous_output: OutPoint::COINBASE_PREVOUT,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
}

/// Bitcoin transaction output.
///
/// Defines new coins to be created as a result of the transaction,
/// along with spending conditions ("script", aka "output script"),
/// which an input spending it must satisfy.
///
/// An output that is not yet spent by an input is called Unspent Transaction Output ("UTXO").
///
/// ### Bitcoin Core References
///
/// * [CTxOut definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L148)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg(feature = "alloc")]
pub struct TxOut {
    /// The value of the output, in satoshis.
    #[cfg_attr(feature = "serde", serde(with = "crate::amount::serde::as_sat"))]
    pub value: Amount,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: ScriptBuf,
}

/// A reference to a transaction output.
///
/// ### Bitcoin Core References
///
/// * [COutPoint definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/transaction.h#L26)
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}
#[cfg(feature = "serde")]
internals::serde_struct_human_string_impl!(OutPoint, "an OutPoint", txid, vout);

impl OutPoint {
    /// The number of bytes that an outpoint contributes to the size of a transaction.
    pub const SIZE: usize = 32 + 4; // The serialized lengths of txid and vout.

    /// The `OutPoint` used in a coinbase prevout.
    ///
    /// This is used as the dummy input for coinbase transactions because they don't have any
    /// previous outputs. In other words, does not point to a real transaction.
    pub const COINBASE_PREVOUT: Self = Self { txid: Txid::COINBASE_PREVOUT, vout: u32::MAX };
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

#[cfg(feature = "alloc")]
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
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    parse::int_from_str(s).map_err(ParseOutPointError::Vout)
}

/// An error in parsing an [`OutPoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "alloc")]
pub enum ParseOutPointError {
    /// Error in TXID part.
    Txid(hex::HexToArrayError),
    /// Error in vout part.
    Vout(parse::ParseIntError),
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
}

#[cfg(feature = "alloc")]
impl From<Infallible> for ParseOutPointError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for ParseOutPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseOutPointError::*;

        match *self {
            Txid(ref e) => write_err!(f, "error parsing TXID"; e),
            Vout(ref e) => write_err!(f, "error parsing vout"; e),
            Format => write!(f, "OutPoint not in <txid>:<vout> format"),
            TooLong => write!(f, "vout should be at most 10 digits"),
            VoutNotCanonical => write!(f, "no leading zeroes or + allowed in vout part"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseOutPointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseOutPointError::*;

        match self {
            Txid(e) => Some(e),
            Vout(e) => Some(e),
            Format | TooLong | VoutNotCanonical => None,
        }
    }
}

hashes::hash_newtype! {
    /// A bitcoin transaction hash/transaction ID.
    ///
    /// For compatibility with the existing Bitcoin infrastructure and historical and current
    /// versions of the Bitcoin Core software itself, this and other [`sha256d::Hash`] types, are
    /// serialized in reverse byte order when converted to a hex string via [`std::fmt::Display`]
    /// trait operations.
    ///
    /// See [`hashes::Hash::DISPLAY_BACKWARD`] for more details.
    pub struct Txid(sha256d::Hash);

    /// A bitcoin witness transaction ID.
    pub struct Wtxid(sha256d::Hash);
}

hashes::impl_hex_for_newtype!(Txid, Wtxid);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(Txid, Wtxid);

impl Txid {
    /// The `Txid` used in a coinbase prevout.
    ///
    /// This is used as the "txid" of the dummy input of a coinbase transaction. This is not a real
    /// TXID and should not be used in any other contexts. See [`OutPoint::COINBASE_PREVOUT`].
    pub const COINBASE_PREVOUT: Self = Self::from_byte_array([0; 32]);
}

impl Wtxid {
    /// The `Wtxid` of a coinbase transaction.
    ///
    /// This is used as the wTXID for the coinbase transaction when constructing blocks (in the
    /// witness commitment tree) since the coinbase transaction contains a commitment to all
    /// transactions' wTXIDs but naturally cannot commit to its own.
    pub const COINBASE: Self = Self::from_byte_array([0; 32]);
}

/// The transaction version.
///
/// Currently, as specified by [BIP-68] and [BIP-431], version 1, 2, and 3 are considered standard.
///
/// Standardness of the inner `u32` is not an invariant because you are free to create transactions
/// of any version, transactions with non-standard version numbers will not be relayed by the
/// Bitcoin network.
///
/// [BIP-68]: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
/// [BIP-431]: https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(u32);

impl Version {
    /// The original Bitcoin transaction version (pre-BIP-68).
    pub const ONE: Self = Self(1);

    /// The second Bitcoin transaction version (post-BIP-68).
    pub const TWO: Self = Self(2);

    /// The third Bitcoin transaction version (post-BIP-431).
    pub const THREE: Self = Self(3);

    /// Constructs a potentially non-standard transaction version.
    ///
    /// This can accept both standard and non-standard versions.
    #[inline]
    pub fn maybe_non_standard(version: u32) -> Version { Self(version) }

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
    pub fn is_standard(&self) -> bool {
        *self == Version::ONE || *self == Version::TWO || *self == Version::THREE
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self { version.0 }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Transaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Transaction {
            version: Version::arbitrary(u)?,
            lock_time: absolute::LockTime::arbitrary(u)?,
            input: Vec::<TxIn>::arbitrary(u)?,
            output: Vec::<TxOut>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for TxIn {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(TxIn {
            previous_output: OutPoint::arbitrary(u)?,
            script_sig: ScriptBuf::arbitrary(u)?,
            sequence: Sequence::arbitrary(u)?,
            witness: Witness::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for TxOut {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(TxOut { value: Amount::arbitrary(u)?, script_pubkey: ScriptBuf::arbitrary(u)? })
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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Txid {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = u.arbitrary()?;
        let t = sha256d::Hash::from_byte_array(arbitrary_bytes);
        Ok(Txid(t))
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_functions() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xAA; 32]), // Arbitrary invalid dummy value.
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let txout = TxOut { value: Amount::from_sat(123456789), script_pubkey: ScriptBuf::new() };

        let tx_orig = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::from_consensus(1738968231), // The time this was written
            input: vec![txin.clone()],
            output: vec![txout.clone()],
        };

        // Test changing the transaction
        let mut tx = tx_orig.clone();
        tx.inputs_mut()[0].previous_output.txid = Txid::from_byte_array([0xFF; 32]);
        tx.outputs_mut()[0].value = Amount::from_sat(987654321);
        assert_eq!(tx.inputs()[0].previous_output.txid.to_byte_array(), [0xFF; 32]);
        assert_eq!(tx.outputs()[0].value.to_sat(), 987654321);

        // Test uses_segwit_serialization
        assert!(!tx.uses_segwit_serialization());
        tx.input[0].witness.push(vec![0xAB, 0xCD, 0xEF]);
        assert!(tx.uses_segwit_serialization());

        // Test partial ord
        assert!(tx > tx_orig);
    }

    #[test]
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

        // Check TooLong error
        outpoint_str.push_str("0000000000");
        let outpoint: Result<OutPoint, ParseOutPointError> = outpoint_str.parse();
        assert_eq!(outpoint, Err(ParseOutPointError::TooLong));
    }

    #[test]
    fn canonical_vout() {
        assert_eq!(parse_vout("0").unwrap(), 0);
        assert_eq!(parse_vout("1").unwrap(), 1);
        assert!(parse_vout("01").is_err()); // Leading zero not allowed
        assert!(parse_vout("+1").is_err()); // Non digits not allowed
    }
}
