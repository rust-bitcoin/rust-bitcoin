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

use core::{cmp, fmt, str};

use hashes::{sha256d, Hash};
use internals::write_err;
use io::{BufRead, Write};
use units::parse::{self, PrefixedHexError, UnprefixedHexError};
use units::{FeeRate, Weight};

use crate::consensus::{encode, Decodable, Encodable};
use crate::internal_macros::{impl_consensus_encoding, impl_hashencode};
use crate::locktime::absolute::{self, Height, Time};
use crate::locktime::relative::{self, TimeOverflowError};
use crate::prelude::*;
use crate::script::{Script, ScriptBuf};
use crate::witness::Witness;
use crate::{Amount, SignedAmount, VarInt};

#[rustfmt::skip]                // Keep public re-exports separate.
#[cfg(feature = "bitcoinconsensus")]
#[doc(inline)]
pub use crate::consensus::validation::TxVerifyError;

hashes::hash_newtype! {
    /// A bitcoin transaction hash/transaction ID.
    ///
    /// For compatibility with the existing Bitcoin infrastructure and historical and current
    /// versions of the Bitcoin Core software itself, this and other [`sha256d::Hash`] types, are
    /// serialized in reverse byte order when converted to a hex string via [`std::fmt::Display`]
    /// trait operations. See [`hashes::Hash::DISPLAY_BACKWARD`] for more details.
    pub struct Txid(sha256d::Hash);

    /// A bitcoin witness transaction ID.
    pub struct Wtxid(sha256d::Hash);
}
impl_hashencode!(Txid);
impl_hashencode!(Wtxid);

/// The marker MUST be a 1-byte zero value: 0x00. (BIP-141)
const SEGWIT_MARKER: u8 = 0x00;
/// The flag MUST be a 1-byte non-zero value. Currently, 0x01 MUST be used. (BIP-141)
const SEGWIT_FLAG: u8 = 0x01;

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
crate::serde_utils::serde_struct_human_string_impl!(OutPoint, "an OutPoint", txid, vout);

impl OutPoint {
    /// The number of bytes that an outpoint contributes to the size of a transaction.
    const SIZE: usize = 32 + 4; // The serialized lengths of txid and vout.

    /// Creates a new [`OutPoint`].
    #[inline]
    pub const fn new(txid: Txid, vout: u32) -> OutPoint { OutPoint { txid, vout } }

    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have any previous outputs.
    #[inline]
    pub fn null() -> OutPoint { OutPoint { txid: Txid::all_zeros(), vout: u32::MAX } }

    /// Checks if an `OutPoint` is "null".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::consensus::params;
    /// use bitcoin::constants::genesis_block;
    /// use bitcoin::Network;
    ///
    /// let block = genesis_block(&params::MAINNET);
    /// let tx = &block.txdata[0];
    ///
    /// // Coinbase transactions don't have any previous output.
    /// assert!(tx.input[0].previous_output.is_null());
    /// ```
    #[inline]
    pub fn is_null(&self) -> bool { *self == OutPoint::null() }
}

impl Default for OutPoint {
    fn default() -> Self { OutPoint::null() }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// An error in parsing an OutPoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

internals::impl_from_infallible!(ParseOutPointError);

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

/// Parses a string-encoded transaction index (vout).
///
/// Does not permit leading zeroes or non-digit characters.
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    parse::int(s).map_err(ParseOutPointError::Vout)
}

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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
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

impl TxIn {
    /// Returns the input base weight.
    ///
    /// Base weight excludes the witness and script.
    const BASE_WEIGHT: Weight =
        Weight::from_vb_unwrap(OutPoint::SIZE as u64 + Sequence::SIZE as u64);

    /// Returns true if this input enables the [`absolute::LockTime`] (aka `nLockTime`) of its
    /// [`Transaction`].
    ///
    /// `nLockTime` is enabled if *any* input enables it. See [`Transaction::is_lock_time_enabled`]
    ///  to check the overall state. If none of the inputs enables it, the lock time value is simply
    ///  ignored. If this returns false and OP_CHECKLOCKTIMEVERIFY is used in the redeem script with
    ///  this input then the script execution will fail [BIP-0065].
    ///
    /// [BIP-65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
    pub fn enables_lock_time(&self) -> bool { self.sequence != Sequence::MAX }

    /// The weight of the TxIn when it's included in a legacy transaction (i.e., a transaction
    /// having only legacy inputs).
    ///
    /// The witness weight is ignored here even when the witness is non-empty.
    /// If you want the witness to be taken into account, use `TxIn::segwit_weight` instead.
    ///
    /// Keep in mind that when adding a TxIn to a transaction, the total weight of the transaction
    /// might increase more than `TxIn::legacy_weight`. This happens when the new input added causes
    /// the input length `VarInt` to increase its encoding length.
    pub fn legacy_weight(&self) -> Weight {
        Weight::from_non_witness_data_size(self.base_size() as u64)
    }

    /// The weight of the TxIn when it's included in a segwit transaction (i.e., a transaction
    /// having at least one segwit input).
    ///
    /// This always takes into account the witness, even when empty, in which
    /// case 1WU for the witness length varint (`00`) is included.
    ///
    /// Keep in mind that when adding a TxIn to a transaction, the total weight of the transaction
    /// might increase more than `TxIn::segwit_weight`. This happens when:
    /// - the new input added causes the input length `VarInt` to increase its encoding length
    /// - the new input is the first segwit input added - this will add an additional 2WU to the
    ///   transaction weight to take into account the segwit marker
    pub fn segwit_weight(&self) -> Weight {
        Weight::from_non_witness_data_size(self.base_size() as u64)
            + Weight::from_witness_data_size(self.witness.size() as u64)
    }

    /// Returns the base size of this input.
    ///
    /// Base size excludes the witness data (see [`Self::total_size`]).
    pub fn base_size(&self) -> usize {
        let mut size = OutPoint::SIZE;

        size += VarInt::from(self.script_sig.len()).size();
        size += self.script_sig.len();

        size + Sequence::SIZE
    }

    /// Returns the total number of bytes that this input contributes to a transaction.
    ///
    /// Total size includes the witness data (for base size see [`Self::base_size`]).
    pub fn total_size(&self) -> usize { self.base_size() + self.witness.size() }
}

impl Default for TxIn {
    fn default() -> TxIn {
        TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }
    }
}

/// Bitcoin transaction input sequence number.
///
/// The sequence field is used for:
/// - Indicating whether absolute lock-time (specified in `lock_time` field of [`Transaction`])
///   is enabled.
/// - Indicating and encoding [BIP-68] relative lock-times.
/// - Indicating whether a transaction opts-in to [BIP-125] replace-by-fee.
///
/// Note that transactions spending an output with `OP_CHECKLOCKTIMEVERIFY`MUST NOT use
/// `Sequence::MAX` for the corresponding input. [BIP-65]
///
/// [BIP-65]: <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
/// [BIP-68]: <https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki>
/// [BIP-125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Sequence(pub u32);

impl Sequence {
    /// The maximum allowable sequence number.
    ///
    /// This sequence number disables absolute lock time and replace-by-fee.
    pub const MAX: Self = Sequence(0xFFFFFFFF);
    /// Zero value sequence.
    ///
    /// This sequence number enables replace-by-fee and absolute lock time.
    pub const ZERO: Self = Sequence(0);
    /// The sequence number that enables absolute lock time but disables replace-by-fee
    /// and relative lock time.
    pub const ENABLE_LOCKTIME_NO_RBF: Self = Sequence::MIN_NO_RBF;
    /// The sequence number that enables replace-by-fee and absolute lock time but
    /// disables relative lock time.
    pub const ENABLE_RBF_NO_LOCKTIME: Self = Sequence(0xFFFFFFFD);

    /// The number of bytes that a sequence number contributes to the size of a transaction.
    const SIZE: usize = 4; // Serialized length of a u32.

    /// The lowest sequence number that does not opt-in for replace-by-fee.
    ///
    /// A transaction is considered to have opted in to replacement of itself
    /// if any of it's inputs have a `Sequence` number less than this value
    /// (Explicit Signalling [BIP-125]).
    ///
    /// [BIP-125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki]>
    const MIN_NO_RBF: Self = Sequence(0xFFFFFFFE);
    /// BIP-68 relative lock time disable flag mask.
    const LOCK_TIME_DISABLE_FLAG_MASK: u32 = 0x80000000;
    /// BIP-68 relative lock time type flag mask.
    const LOCK_TYPE_MASK: u32 = 0x00400000;

    /// Returns `true` if the sequence number enables absolute lock-time ([`Transaction::lock_time`]).
    #[inline]
    pub fn enables_absolute_lock_time(&self) -> bool { *self != Sequence::MAX }

    /// Returns `true` if the sequence number indicates that the transaction is finalized.
    ///
    /// Instead of this method please consider using `!enables_absolute_lock_time` because it
    /// is equivalent and improves readability for those not steeped in Bitcoin folklore.
    ///
    /// ## Historical note
    ///
    /// The term 'final' is an archaic Bitcoin term, it may have come about because the sequence
    /// number in the original Bitcoin code was intended to be incremented in order to replace a
    /// transaction, so once the sequence number got to `u64::MAX` it could no longer be increased,
    /// hence it was 'final'.
    ///
    ///
    /// Some other references to the term:
    /// - `CTxIn::SEQUENCE_FINAL` in the Bitcoin Core code.
    /// - [BIP-112]: "BIP 68 prevents a non-final transaction from being selected for inclusion in a
    ///   block until the corresponding input has reached the specified age"
    ///
    /// [BIP-112]: <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
    #[inline]
    pub fn is_final(&self) -> bool { !self.enables_absolute_lock_time() }

    /// Returns true if the transaction opted-in to BIP125 replace-by-fee.
    ///
    /// Replace by fee is signaled by the sequence being less than 0xfffffffe which is checked by
    /// this method. Note, this is the highest "non-final" value (see [`Sequence::is_final`]).
    #[inline]
    pub fn is_rbf(&self) -> bool { *self < Sequence::MIN_NO_RBF }

    /// Returns `true` if the sequence has a relative lock-time.
    #[inline]
    pub fn is_relative_lock_time(&self) -> bool {
        self.0 & Sequence::LOCK_TIME_DISABLE_FLAG_MASK == 0
    }

    /// Returns `true` if the sequence number encodes a block based relative lock-time.
    #[inline]
    pub fn is_height_locked(&self) -> bool {
        self.is_relative_lock_time() & (self.0 & Sequence::LOCK_TYPE_MASK == 0)
    }

    /// Returns `true` if the sequence number encodes a time interval based relative lock-time.
    #[inline]
    pub fn is_time_locked(&self) -> bool {
        self.is_relative_lock_time() & (self.0 & Sequence::LOCK_TYPE_MASK > 0)
    }

    /// Creates a `Sequence` from a prefixed hex string.
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let lock_time = parse::hex_u32_prefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Creates a `Sequence` from an unprefixed hex string.
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        let lock_time = parse::hex_u32_unprefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Creates a relative lock-time using block height.
    #[inline]
    pub fn from_height(height: u16) -> Self { Sequence(u32::from(height)) }

    /// Creates a relative lock-time using time intervals where each interval is equivalent
    /// to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin
    #[inline]
    pub fn from_512_second_intervals(intervals: u16) -> Self {
        Sequence(u32::from(intervals) | Sequence::LOCK_TYPE_MASK)
    }

    /// Creates a relative lock-time from seconds, converting the seconds into 512 second
    /// interval with floor division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        if let Ok(interval) = u16::try_from(seconds / 512) {
            Ok(Sequence::from_512_second_intervals(interval))
        } else {
            Err(TimeOverflowError::new(seconds))
        }
    }

    /// Creates a relative lock-time from seconds, converting the seconds into 512 second
    /// interval with ceiling division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        if let Ok(interval) = u16::try_from((seconds + 511) / 512) {
            Ok(Sequence::from_512_second_intervals(interval))
        } else {
            Err(TimeOverflowError::new(seconds))
        }
    }

    /// Creates a sequence from a u32 value.
    #[inline]
    pub fn from_consensus(n: u32) -> Self { Sequence(n) }

    /// Returns the inner 32bit integer value of Sequence.
    #[inline]
    pub fn to_consensus_u32(self) -> u32 { self.0 }

    /// Creates a [`relative::LockTime`] from this [`Sequence`] number.
    #[inline]
    pub fn to_relative_lock_time(&self) -> Option<relative::LockTime> {
        use crate::locktime::relative::{Height, LockTime, Time};

        if !self.is_relative_lock_time() {
            return None;
        }

        let lock_value = self.low_u16();

        if self.is_time_locked() {
            Some(LockTime::from(Time::from_512_second_intervals(lock_value)))
        } else {
            Some(LockTime::from(Height::from(lock_value)))
        }
    }

    /// Returns the low 16 bits from sequence number.
    ///
    /// BIP-68 only uses the low 16 bits for relative lock value.
    fn low_u16(&self) -> u16 { self.0 as u16 }
}

impl Default for Sequence {
    /// The default value of sequence is 0xffffffff.
    fn default() -> Self { Sequence::MAX }
}

impl From<Sequence> for u32 {
    fn from(sequence: Sequence) -> u32 { sequence.0 }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::LowerHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl fmt::Debug for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // 10 because its 8 digits + 2 for the '0x'
        write!(f, "Sequence({:#010x})", self.0)
    }
}

units::impl_parse_str_from_int_infallible!(Sequence, u32, from_consensus);

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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct TxOut {
    /// The value of the output, in satoshis.
    pub value: Amount,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: ScriptBuf,
}

impl TxOut {
    /// This is used as a "null txout" in consensus signing code.
    pub const NULL: Self =
        TxOut { value: Amount::from_sat(0xffffffffffffffff), script_pubkey: ScriptBuf::new() };

    /// The weight of this output.
    ///
    /// Keep in mind that when adding a [`TxOut`] to a [`Transaction`] the total weight of the
    /// transaction might increase more than `TxOut::weight`. This happens when the new output added
    /// causes the output length `VarInt` to increase its encoding length.
    ///
    /// # Panics
    ///
    /// If output size * 4 overflows, this should never happen under normal conditions. Use
    /// `Weght::from_vb_checked(self.size() as u64)` if you are concerned.
    pub fn weight(&self) -> Weight {
        // Size is equivalent to virtual size since all bytes of a TxOut are non-witness bytes.
        Weight::from_vb(self.size() as u64).expect("should never happen under normal conditions")
    }

    /// Returns the total number of bytes that this output contributes to a transaction.
    ///
    /// There is no difference between base size vs total size for outputs.
    pub fn size(&self) -> usize { size_from_script_pubkey(&self.script_pubkey) }

    /// Creates a `TxOut` with given script and the smallest possible `value` that is **not** dust
    /// per current Core policy.
    ///
    /// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
    /// This function uses the default value of 0.00003 BTC/kB (3 sat/vByte).
    ///
    /// To use a custom value, use [`minimal_non_dust_custom`].
    ///
    /// [`minimal_non_dust_custom`]: TxOut::minimal_non_dust_custom
    pub fn minimal_non_dust(script_pubkey: ScriptBuf) -> Self {
        TxOut { value: script_pubkey.minimal_non_dust(), script_pubkey }
    }

    /// Creates a `TxOut` with given script and the smallest possible `value` that is **not** dust
    /// per current Core policy.
    ///
    /// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
    /// This function lets you set the fee rate used in dust calculation.
    ///
    /// The current default value in Bitcoin Core (as of v26) is 3 sat/vByte.
    ///
    /// To use the default Bitcoin Core value, use [`minimal_non_dust`].
    ///
    /// [`minimal_non_dust`]: TxOut::minimal_non_dust
    pub fn minimal_non_dust_custom(script_pubkey: ScriptBuf, dust_relay_fee: FeeRate) -> Self {
        TxOut { value: script_pubkey.minimal_non_dust_custom(dust_relay_fee), script_pubkey }
    }
}

/// Returns the total number of bytes that this script pubkey would contribute to a transaction.
fn size_from_script_pubkey(script_pubkey: &Script) -> usize {
    let len = script_pubkey.len();
    Amount::SIZE + VarInt::from(len).size() + len
}

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
/// in the post-BIP141 Segwit format which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized in the pre-BIP141
/// format.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if the transaction has no inputs, it is serialized in the BIP141 style. Be
/// aware that this differs from the transaction format in PSBT, which _never_
/// uses BIP141. (Ordinarily there is no conflict, since in PSBT transactions
/// are always unsigned and therefore their inputs have empty witnesses.)
///
/// The specific ambiguity is that Segwit uses the flag bytes `0001` where an old
/// serializer would read the number of transaction inputs. The old serializer
/// would interpret this as "no inputs, one output", which means the transaction
/// is invalid, and simply reject it. Segwit further specifies that this encoding
/// should *only* be used when some input has a nonempty witness; that is,
/// witness-less transactions should be encoded in the traditional format.
///
/// However, in protocols where transactions may legitimately have 0 inputs, e.g.
/// when parties are cooperatively funding a transaction, the "00 means Segwit"
/// heuristic does not work. Since Segwit requires such a transaction be encoded
/// in the original transaction format (since it has no inputs and therefore
/// no input witnesses), a traditionally encoded transaction may have the `0001`
/// Segwit flag in it, which confuses most Segwit parsers including the one in
/// Bitcoin Core.
///
/// We therefore deviate from the spec by always using the Segwit witness encoding
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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Transaction {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
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

impl cmp::PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> { Some(self.cmp(other)) }
}
impl cmp::Ord for Transaction {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.version
            .cmp(&other.version)
            .then(self.lock_time.to_consensus_u32().cmp(&other.lock_time.to_consensus_u32()))
            .then(self.input.cmp(&other.input))
            .then(self.output.cmp(&other.output))
    }
}

impl Transaction {
    // https://github.com/bitcoin/bitcoin/blob/44b05bf3fef2468783dcebf651654fdd30717e7e/src/policy/policy.h#L27
    /// Maximum transaction weight for Bitcoin Core 25.0.
    pub const MAX_STANDARD_WEIGHT: Weight = Weight::from_wu(400_000);

    /// Computes a "normalized TXID" which does not include any signatures.
    ///
    /// This method is deprecated.  Use `compute_ntxid` instead.
    #[deprecated(
        since = "0.31.0",
        note = "ntxid has been renamed to compute_ntxid to note that it's computationally expensive.  use compute_ntxid() instead."
    )]
    pub fn ntxid(&self) -> sha256d::Hash { self.compute_ntxid() }

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
    /// This method is deprecated.  Use `compute_txid` instead.
    #[deprecated(
        since = "0.31.0",
        note = "txid has been renamed to compute_txid to note that it's computationally expensive.  use compute_txid() instead."
    )]
    pub fn txid(&self) -> Txid { self.compute_txid() }

    /// Computes the [`Txid`].
    ///
    /// Hashes the transaction **excluding** the segwit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-segwit transactions which do not have any segwit data,
    /// this will be equal to [`Transaction::compute_wtxid()`].
    #[doc(alias = "txid")]
    pub fn compute_txid(&self) -> Txid {
        let mut enc = Txid::engine();
        self.version.consensus_encode(&mut enc).expect("engines don't error");
        self.input.consensus_encode(&mut enc).expect("engines don't error");
        self.output.consensus_encode(&mut enc).expect("engines don't error");
        self.lock_time.consensus_encode(&mut enc).expect("engines don't error");
        Txid::from_engine(enc)
    }

    /// Computes the segwit version of the transaction id.
    ///
    /// This method is deprecated.  Use `compute_wtxid` instead.
    #[deprecated(
        since = "0.31.0",
        note = "wtxid has been renamed to compute_wtxid to note that it's computationally expensive.  use compute_wtxid() instead."
    )]
    pub fn wtxid(&self) -> Wtxid { self.compute_wtxid() }

    /// Computes the segwit version of the transaction id.
    ///
    /// Hashes the transaction **including** all segwit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-segwit transactions which do not have any segwit data,
    /// this will be equal to [`Transaction::txid()`].
    #[doc(alias = "wtxid")]
    pub fn compute_wtxid(&self) -> Wtxid {
        let mut enc = Wtxid::engine();
        self.consensus_encode(&mut enc).expect("engines don't error");
        Wtxid::from_engine(enc)
    }

    /// Returns the weight of this transaction, as defined by BIP-141.
    ///
    /// > Transaction weight is defined as Base transaction size * 3 + Total transaction size (ie.
    /// > the same method as calculating Block weight from Base size and Total size).
    ///
    /// For transactions with an empty witness, this is simply the consensus-serialized size times
    /// four. For transactions with a witness, this is the non-witness consensus-serialized size
    /// multiplied by three plus the with-witness consensus-serialized size.
    ///
    /// For transactions with no inputs, this function will return a value 2 less than the actual
    /// weight of the serialized transaction. The reason is that zero-input transactions, post-segwit,
    /// cannot be unambiguously serialized; we make a choice that adds two extra bytes. For more
    /// details see [BIP 141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    /// which uses a "input count" of `0x00` as a `marker` for a Segwit-encoded transaction.
    ///
    /// If you need to use 0-input transactions, we strongly recommend you do so using the PSBT
    /// API. The unsigned transaction encoded within PSBT is always a non-segwit transaction
    /// and can therefore avoid this ambiguity.
    #[inline]
    pub fn weight(&self) -> Weight {
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        let wu = self.base_size() * 3 + self.total_size();
        Weight::from_wu_usize(wu)
    }

    /// Returns the base transaction size.
    ///
    /// > Base transaction size is the size of the transaction serialised with the witness data stripped.
    pub fn base_size(&self) -> usize {
        let mut size: usize = 4; // Serialized length of a u32 for the version number.

        size += VarInt::from(self.input.len()).size();
        size += self.input.iter().map(|input| input.base_size()).sum::<usize>();

        size += VarInt::from(self.output.len()).size();
        size += self.output.iter().map(|output| output.size()).sum::<usize>();

        size + absolute::LockTime::SIZE
    }

    /// Returns the total transaction size.
    ///
    /// > Total transaction size is the transaction size in bytes serialized as described in BIP144,
    /// > including base data and witness data.
    #[inline]
    pub fn total_size(&self) -> usize {
        let mut size: usize = 4; // Serialized length of a u32 for the version number.
        let uses_segwit = self.uses_segwit_serialization();

        if uses_segwit {
            size += 2; // 1 byte for the marker and 1 for the flag.
        }

        size += VarInt::from(self.input.len()).size();
        size += self
            .input
            .iter()
            .map(|input| if uses_segwit { input.total_size() } else { input.base_size() })
            .sum::<usize>();

        size += VarInt::from(self.output.len()).size();
        size += self.output.iter().map(|output| output.size()).sum::<usize>();

        size + absolute::LockTime::SIZE
    }

    /// Returns the "virtual size" (vsize) of this transaction.
    ///
    /// Will be `ceil(weight / 4.0)`. Note this implements the virtual size as per [`BIP141`], which
    /// is different to what is implemented in Bitcoin Core. The computation should be the same for
    /// any remotely sane transaction, and a standardness-rule-correct version is available in the
    /// [`policy`] module.
    ///
    /// > Virtual transaction size is defined as Transaction weight / 4 (rounded up to the next integer).
    ///
    /// [`BIP141`]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    /// [`policy`]: ../../policy/index.html
    #[inline]
    pub fn vsize(&self) -> usize {
        // No overflow because it's computed from data in memory
        self.weight().to_vbytes_ceil() as usize
    }

    /// Checks if this is a coinbase transaction.
    ///
    /// The first transaction in the block distributes the mining reward and is called the coinbase
    /// transaction. It is impossible to check if the transaction is first in the block, so this
    /// function checks the structure of the transaction instead - the previous output must be
    /// all-zeros (creates satoshis "out of thin air").
    #[doc(alias = "is_coin_base")] // method previously had this name
    pub fn is_coinbase(&self) -> bool {
        self.input.len() == 1 && self.input[0].previous_output.is_null()
    }

    /// Returns `true` if the transaction itself opted in to be BIP-125-replaceable (RBF).
    ///
    /// # Warning
    ///
    /// **Incorrectly relying on RBF may lead to monetary loss!**
    ///
    /// This **does not** cover the case where a transaction becomes replaceable due to ancestors
    /// being RBF. Please note that transactions **may be replaced** even if they **do not** include
    /// the RBF signal: <https://bitcoinops.org/en/newsletters/2022/10/19/#transaction-replacement-option>.
    pub fn is_explicitly_rbf(&self) -> bool {
        self.input.iter().any(|input| input.sequence.is_rbf())
    }

    /// Returns true if this [`Transaction`]'s absolute timelock is satisfied at `height`/`time`.
    ///
    /// # Returns
    ///
    /// By definition if the lock time is not enabled the transaction's absolute timelock is
    /// considered to be satisfied i.e., there are no timelock constraints restricting this
    /// transaction from being mined immediately.
    pub fn is_absolute_timelock_satisfied(&self, height: Height, time: Time) -> bool {
        if !self.is_lock_time_enabled() {
            return true;
        }
        self.lock_time.is_satisfied_by(height, time)
    }

    /// Returns `true` if this transactions nLockTime is enabled ([BIP-65]).
    ///
    /// [BIP-65]: https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
    pub fn is_lock_time_enabled(&self) -> bool { self.input.iter().any(|i| i.enables_lock_time()) }

    /// Returns an iterator over lengths of `script_pubkey`s in the outputs.
    ///
    /// This is useful in combination with [`predict_weight`] if you have the transaction already
    /// constructed with a dummy value in the fee output which you'll adjust after calculating the
    /// weight.
    pub fn script_pubkey_lens(&self) -> impl Iterator<Item = usize> + '_ {
        self.output.iter().map(|txout| txout.script_pubkey.len())
    }

    /// Counts the total number of sigops.
    ///
    /// This value is for pre-taproot transactions only.
    ///
    /// > In taproot, a different mechanism is used. Instead of having a global per-block limit,
    /// > there is a per-transaction-input limit, proportional to the size of that input.
    /// > ref: <https://bitcoin.stackexchange.com/questions/117356/what-is-sigop-signature-operation#117359>
    ///
    /// The `spent` parameter is a closure/function that looks up the output being spent by each input
    /// It takes in an [`OutPoint`] and returns a [`TxOut`]. If you can't provide this, a placeholder of
    /// `|_| None` can be used. Without access to the previous [`TxOut`], any sigops in a redeemScript (P2SH)
    /// as well as any segwit sigops will not be counted for that input.
    pub fn total_sigop_cost<S>(&self, mut spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        let mut cost = self.count_p2pk_p2pkh_sigops().saturating_mul(4);

        // coinbase tx is correctly handled because `spent` will always returns None.
        cost = cost.saturating_add(self.count_p2sh_sigops(&mut spent).saturating_mul(4));
        cost.saturating_add(self.count_witness_sigops(&mut spent))
    }

    /// Gets the sigop count.
    ///
    /// Counts sigops for this transaction's input scriptSigs and output scriptPubkeys i.e., doesn't
    /// count sigops in the redeemScript for p2sh or the sigops in the witness (use
    /// `count_p2sh_sigops` and `count_witness_sigops` respectively).
    fn count_p2pk_p2pkh_sigops(&self) -> usize {
        let mut count: usize = 0;
        for input in &self.input {
            // 0 for p2wpkh, p2wsh, and p2sh (including wrapped segwit).
            count = count.saturating_add(input.script_sig.count_sigops_legacy());
        }
        for output in &self.output {
            count = count.saturating_add(output.script_pubkey.count_sigops_legacy());
        }
        count
    }

    /// Does not include wrapped segwit (see `count_witness_sigops`).
    fn count_p2sh_sigops<S>(&self, spent: &mut S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        fn count_sigops(prevout: &TxOut, input: &TxIn) -> usize {
            let mut count: usize = 0;
            if prevout.script_pubkey.is_p2sh() {
                if let Some(redeem) = input.script_sig.last_pushdata() {
                    count =
                        count.saturating_add(Script::from_bytes(redeem.as_bytes()).count_sigops());
                }
            }
            count
        }

        let mut count: usize = 0;
        for input in &self.input {
            if let Some(prevout) = spent(&input.previous_output) {
                count = count.saturating_add(count_sigops(&prevout, input));
            }
        }
        count
    }

    /// Includes wrapped segwit (returns 0 for taproot spends).
    fn count_witness_sigops<S>(&self, spent: &mut S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        fn count_sigops_with_witness_program(witness: &Witness, witness_program: &Script) -> usize {
            if witness_program.is_p2wpkh() {
                1
            } else if witness_program.is_p2wsh() {
                // Treat the last item of the witness as the witnessScript
                return witness
                    .last()
                    .map(Script::from_bytes)
                    .map(|s| s.count_sigops())
                    .unwrap_or(0);
            } else {
                0
            }
        }

        fn count_sigops(prevout: TxOut, input: &TxIn) -> usize {
            let script_sig = &input.script_sig;
            let witness = &input.witness;

            let witness_program = if prevout.script_pubkey.is_witness_program() {
                &prevout.script_pubkey
            } else if prevout.script_pubkey.is_p2sh() && script_sig.is_push_only() {
                // If prevout is P2SH and scriptSig is push only
                // then we wrap the last push (redeemScript) in a Script
                if let Some(push_bytes) = script_sig.last_pushdata() {
                    Script::from_bytes(push_bytes.as_bytes())
                } else {
                    return 0;
                }
            } else {
                return 0;
            };

            // This will return 0 if the redeemScript wasn't a witness program
            count_sigops_with_witness_program(witness, witness_program)
        }

        let mut count: usize = 0;
        for input in &self.input {
            if let Some(prevout) = spent(&input.previous_output) {
                count = count.saturating_add(count_sigops(prevout, input));
            }
        }
        count
    }

    /// Returns whether or not to serialize transaction as specified in BIP-144.
    // FIXME: This used to be private.
    pub fn uses_segwit_serialization(&self) -> bool {
        if self.input.iter().any(|input| !input.witness.is_empty()) {
            return true;
        }
        // To avoid serialization ambiguity, no inputs means we use BIP141 serialization (see
        // `Transaction` docs for full explanation).
        self.input.is_empty()
    }

    /// Returns a reference to the input at `input_index` if it exists.
    #[inline]
    pub fn tx_in(&self, input_index: usize) -> Result<&TxIn, InputsIndexError> {
        self.input
            .get(input_index)
            .ok_or(IndexOutOfBoundsError { index: input_index, length: self.input.len() }.into())
    }

    /// Returns a reference to the output at `output_index` if it exists.
    #[inline]
    pub fn tx_out(&self, output_index: usize) -> Result<&TxOut, OutputsIndexError> {
        self.output
            .get(output_index)
            .ok_or(IndexOutOfBoundsError { index: output_index, length: self.output.len() }.into())
    }
}

/// Error attempting to do an out of bounds access on the transaction inputs vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputsIndexError(pub IndexOutOfBoundsError);

impl fmt::Display for InputsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "invalid input index"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl From<IndexOutOfBoundsError> for InputsIndexError {
    fn from(e: IndexOutOfBoundsError) -> Self { Self(e) }
}

/// Error attempting to do an out of bounds access on the transaction outputs vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputsIndexError(pub IndexOutOfBoundsError);

impl fmt::Display for OutputsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "invalid output index"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl From<IndexOutOfBoundsError> for OutputsIndexError {
    fn from(e: IndexOutOfBoundsError) -> Self { Self(e) }
}

/// Error attempting to do an out of bounds access on a vector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IndexOutOfBoundsError {
    /// Attempted index access.
    pub index: usize,
    /// Length of the vector where access was attempted.
    pub length: usize,
}

impl fmt::Display for IndexOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index {} is out-of-bounds for vector with length {}", self.index, self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// The transaction version.
///
/// Currently, as specified by [BIP-68], only version 1 and 2 are considered standard.
///
/// Standardness of the inner `i32` is not an invariant because you are free to create transactions
/// of any version, transactions with non-standard version numbers will not be relayed by the
/// Bitcoin network.
///
/// [BIP-68]: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(pub i32);

impl Version {
    /// The original Bitcoin transaction version (pre-BIP-68).
    pub const ONE: Self = Self(1);

    /// The second Bitcoin transaction version (post-BIP-68).
    pub const TWO: Self = Self(2);

    /// Creates a non-standard transaction version.
    pub fn non_standard(version: i32) -> Version { Self(version) }

    /// Returns true if this transaction version number is considered standard.
    pub fn is_standard(&self) -> bool { *self == Version::ONE || *self == Version::TWO }
}

impl Encodable for Version {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl_consensus_encoding!(TxOut, value, script_pubkey);

impl Encodable for OutPoint {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = self.txid.consensus_encode(w)?;
        Ok(len + self.vout.consensus_encode(w)?)
    }
}
impl Decodable for OutPoint {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(OutPoint {
            txid: Decodable::consensus_decode(r)?,
            vout: Decodable::consensus_decode(r)?,
        })
    }
}

impl Encodable for TxIn {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.previous_output.consensus_encode(w)?;
        len += self.script_sig.consensus_encode(w)?;
        len += self.sequence.consensus_encode(w)?;
        Ok(len)
    }
}
impl Decodable for TxIn {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        Ok(TxIn {
            previous_output: Decodable::consensus_decode_from_finite_reader(r)?,
            script_sig: Decodable::consensus_decode_from_finite_reader(r)?,
            sequence: Decodable::consensus_decode_from_finite_reader(r)?,
            witness: Witness::default(),
        })
    }
}

impl Encodable for Sequence {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Sequence {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Sequence)
    }
}

impl Encodable for Transaction {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;

        // Legacy transaction serialization format only includes inputs and outputs.
        if !self.uses_segwit_serialization() {
            len += self.input.consensus_encode(w)?;
            len += self.output.consensus_encode(w)?;
        } else {
            // BIP-141 (segwit) transaction serialization also includes marker, flag, and witness data.
            len += SEGWIT_MARKER.consensus_encode(w)?;
            len += SEGWIT_FLAG.consensus_encode(w)?;
            len += self.input.consensus_encode(w)?;
            len += self.output.consensus_encode(w)?;
            for input in &self.input {
                len += input.witness.consensus_encode(w)?;
            }
        }
        len += self.lock_time.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for Transaction {
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let version = Version::consensus_decode_from_finite_reader(r)?;
        let input = Vec::<TxIn>::consensus_decode_from_finite_reader(r)?;
        // segwit
        if input.is_empty() {
            let segwit_flag = u8::consensus_decode_from_finite_reader(r)?;
            match segwit_flag {
                // BIP144 input witnesses
                1 => {
                    let mut input = Vec::<TxIn>::consensus_decode_from_finite_reader(r)?;
                    let output = Vec::<TxOut>::consensus_decode_from_finite_reader(r)?;
                    for txin in input.iter_mut() {
                        txin.witness = Decodable::consensus_decode_from_finite_reader(r)?;
                    }
                    if !input.is_empty() && input.iter().all(|input| input.witness.is_empty()) {
                        Err(encode::Error::ParseFailed("witness flag set but no witnesses present"))
                    } else {
                        Ok(Transaction {
                            version,
                            input,
                            output,
                            lock_time: Decodable::consensus_decode_from_finite_reader(r)?,
                        })
                    }
                }
                // We don't support anything else
                x => Err(encode::Error::UnsupportedSegwitFlag(x)),
            }
        // non-segwit
        } else {
            Ok(Transaction {
                version,
                input,
                output: Decodable::consensus_decode_from_finite_reader(r)?,
                lock_time: Decodable::consensus_decode_from_finite_reader(r)?,
            })
        }
    }
}

impl From<Transaction> for Txid {
    fn from(tx: Transaction) -> Txid { tx.compute_txid() }
}

impl From<&Transaction> for Txid {
    fn from(tx: &Transaction) -> Txid { tx.compute_txid() }
}

impl From<Transaction> for Wtxid {
    fn from(tx: Transaction) -> Wtxid { tx.compute_wtxid() }
}

impl From<&Transaction> for Wtxid {
    fn from(tx: &Transaction) -> Wtxid { tx.compute_wtxid() }
}

/// Computes the value of an output accounting for the cost of spending it.
///
/// The effective value is the value of an output value minus the amount to spend it.  That is, the
/// effective_value can be calculated as: value - (fee_rate * weight).
///
/// Note: the effective value of a [`Transaction`] may increase less than the effective value of
/// a [`TxOut`] when adding another [`TxOut`] to the transaction.  This happens when the new
/// [`TxOut`] added causes the output length `VarInt` to increase its encoding length.
///
/// # Parameters
///
/// * `fee_rate` - the fee rate of the transaction being created.
/// * `satisfaction_weight` - satisfied spending conditions weight.
pub fn effective_value(
    fee_rate: FeeRate,
    satisfaction_weight: Weight,
    value: Amount,
) -> Option<SignedAmount> {
    let weight = satisfaction_weight.checked_add(TxIn::BASE_WEIGHT)?;
    let signed_input_fee = fee_rate.checked_mul_by_weight(weight)?.to_signed().ok()?;
    value.to_signed().ok()?.checked_sub(signed_input_fee)
}

/// Predicts the weight of a to-be-constructed transaction.
///
/// This function computes the weight of a transaction which is not fully known. All that is needed
/// is the lengths of scripts and witness elements.
///
/// # Parameters
///
/// * `inputs` - an iterator which returns `InputWeightPrediction` for each input of the
///   to-be-constructed transaction.
/// * `output_script_lens` - an iterator which returns the length of `script_pubkey` of each output
///   of the to-be-constructed transaction.
///
/// Note that lengths of the scripts and witness elements must be non-serialized, IOW *without* the
/// preceding compact size. The length of preceding compact size is computed and added inside the
/// function for convenience.
///
/// If you  have the transaction already constructed (except for signatures) with a dummy value for
/// fee output you can use the return value of [`Transaction::script_pubkey_lens`] method directly
/// as the second argument.
///
/// # Usage
///
/// When signing a transaction one doesn't know the signature before knowing the transaction fee and
/// the transaction fee is not known before knowing the transaction size which is not known before
/// knowing the signature. This apparent dependency cycle can be broken by knowing the length of the
/// signature without knowing the contents of the signature e.g., we know all Schnorr signatures
/// are 64 bytes long.
///
/// Additionally, some protocols may require calculating the amounts before knowing various parts
/// of the transaction (assuming their length is known).
///
/// # Notes on integer overflow
///
/// Overflows are intentionally not checked because one of the following holds:
///
/// * The transaction is valid (obeys the block size limit) and the code feeds correct values to
///   this function - no overflow can happen.
/// * The transaction will be so large it doesn't fit in the memory - overflow will happen but
///   then the transaction will fail to construct and even if one serialized it on disk directly
///   it'd be invalid anyway so overflow doesn't matter.
/// * The values fed into this function are inconsistent with the actual lengths the transaction
///   will have - the code is already broken and checking overflows doesn't help. Unfortunately
///   this probably cannot be avoided.
pub fn predict_weight<I, O>(inputs: I, output_script_lens: O) -> Weight
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    // This fold() does three things:
    // 1) Counts the inputs and returns the sum as `input_count`.
    // 2) Sums all of the input weights and returns the sum as `partial_input_weight`
    //    For every input: script_size * 4 + witness_size
    //    Since script_size is non-witness data, it gets a 4x multiplier.
    // 3) Counts the number of inputs that have a witness data and returns the count as
    //    `num_inputs_with_witnesses`.
    let (input_count, partial_input_weight, inputs_with_witnesses) = inputs.into_iter().fold(
        (0, 0, 0),
        |(count, partial_input_weight, inputs_with_witnesses), prediction| {
            (
                count + 1,
                partial_input_weight + prediction.weight().to_wu() as usize,
                inputs_with_witnesses + (prediction.witness_size > 0) as usize,
            )
        },
    );

    // This fold() does two things:
    // 1) Counts the outputs and returns the sum as `output_count`.
    // 2) Sums the output script sizes and returns the sum as `output_scripts_size`.
    //    script_len + the length of a VarInt struct that stores the value of script_len
    let (output_count, output_scripts_size) = output_script_lens.into_iter().fold(
        (0, 0),
        |(output_count, total_scripts_size), script_len| {
            let script_size = script_len + VarInt(script_len as u64).size();
            (output_count + 1, total_scripts_size + script_size)
        },
    );
    predict_weight_internal(
        input_count,
        partial_input_weight,
        inputs_with_witnesses,
        output_count,
        output_scripts_size,
    )
}

const fn predict_weight_internal(
    input_count: usize,
    partial_input_weight: usize,
    inputs_with_witnesses: usize,
    output_count: usize,
    output_scripts_size: usize,
) -> Weight {
    // Lengths of txid, index and sequence: (32, 4, 4).
    // Multiply the lengths by 4 since the fields are all non-witness fields.
    let input_weight = partial_input_weight + input_count * 4 * (32 + 4 + 4);

    // The value field of a TxOut is 8 bytes.
    let output_size = 8 * output_count + output_scripts_size;
    let non_input_size =
    // version:
        4 +
    // count varints:
        VarInt(input_count as u64).size() +
        VarInt(output_count as u64).size() +
        output_size +
    // lock_time
        4;
    let weight = if inputs_with_witnesses == 0 {
        non_input_size * 4 + input_weight
    } else {
        non_input_size * 4 + input_weight + input_count - inputs_with_witnesses + 2
    };
    Weight::from_wu(weight as u64)
}

/// Predicts the weight of a to-be-constructed transaction in const context.
///
/// This is a `const` version of [`predict_weight`] which only allows slices due to current Rust
/// limitations around `const fn`. Because of these limitations it may be less efficient than
/// `predict_weight` and thus is intended to be only used in `const` context.
///
/// Please see the documentation of `predict_weight` to learn more about this function.
pub const fn predict_weight_from_slices(
    inputs: &[InputWeightPrediction],
    output_script_lens: &[usize],
) -> Weight {
    let mut partial_input_weight = 0;
    let mut inputs_with_witnesses = 0;

    // for loops not supported in const fn
    let mut i = 0;
    while i < inputs.len() {
        let prediction = inputs[i];
        partial_input_weight += prediction.weight().to_wu() as usize;
        inputs_with_witnesses += (prediction.witness_size > 0) as usize;
        i += 1;
    }

    let mut output_scripts_size = 0;

    i = 0;
    while i < output_script_lens.len() {
        let script_len = output_script_lens[i];
        output_scripts_size += script_len + VarInt(script_len as u64).size();
        i += 1;
    }

    predict_weight_internal(
        inputs.len(),
        partial_input_weight,
        inputs_with_witnesses,
        output_script_lens.len(),
        output_scripts_size,
    )
}

/// Weight prediction of an individual input.
///
/// This helper type collects information about an input to be used in [`predict_weight`] function.
/// It can only be created using the [`new`](InputWeightPrediction::new) function or using other
/// associated constants/methods.
#[derive(Copy, Clone, Debug)]
pub struct InputWeightPrediction {
    script_size: usize,
    witness_size: usize,
}

impl InputWeightPrediction {
    /// Input weight prediction corresponding to spending of P2WPKH output with the largest possible
    /// DER-encoded signature.
    ///
    /// If the input in your transaction uses P2WPKH you can use this instead of
    /// [`InputWeightPrediction::new`].
    ///
    /// This is useful when you **do not** use [signature grinding] and want to ensure you are not
    /// under-paying. See [`ground_p2wpkh`](Self::ground_p2wpkh) if you do use signature grinding.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const P2WPKH_MAX: Self = InputWeightPrediction::from_slice(0, &[72, 33]);

    /// Input weight prediction corresponding to spending of a P2PKH output with the largest possible
    /// DER-encoded signature, and a compressed public key.
    ///
    /// If the input in your transaction uses P2PKH with a compressed key, you can use this instead of
    /// [`InputWeightPrediction::new`].
    ///
    /// This is useful when you **do not** use [signature grinding] and want to ensure you are not
    /// under-paying. See [`ground_p2pkh_compressed`](Self::ground_p2pkh_compressed) if you do use
    /// signature grinding.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const P2PKH_COMPRESSED_MAX: Self = InputWeightPrediction::from_slice(107, &[]);

    /// Input weight prediction corresponding to spending of a P2PKH output with the largest possible
    /// DER-encoded signature, and an uncompressed public key.
    ///
    /// If the input in your transaction uses P2PKH with an uncompressed key, you can use this instead of
    /// [`InputWeightPrediction::new`].
    pub const P2PKH_UNCOMPRESSED_MAX: Self = InputWeightPrediction::from_slice(139, &[]);

    /// Input weight prediction corresponding to spending of taproot output using the key and
    /// default sighash.
    ///
    /// If the input in your transaction uses Taproot key spend you can use this instead of
    /// [`InputWeightPrediction::new`].
    pub const P2TR_KEY_DEFAULT_SIGHASH: Self = InputWeightPrediction::from_slice(0, &[64]);

    /// Input weight prediction corresponding to spending of taproot output using the key and
    /// **non**-default sighash.
    ///
    /// If the input in your transaction uses Taproot key spend you can use this instead of
    /// [`InputWeightPrediction::new`].
    pub const P2TR_KEY_NON_DEFAULT_SIGHASH: Self = InputWeightPrediction::from_slice(0, &[65]);

    /// Input weight prediction corresponding to spending of P2WPKH output using [signature
    /// grinding].
    ///
    /// If the input in your transaction uses P2WPKH and you use signature grinding you can use this
    /// instead of [`InputWeightPrediction::new`]. See [`P2WPKH_MAX`](Self::P2WPKH_MAX) if you don't
    /// use signature grinding.
    ///
    /// Note: `bytes_to_grind` is usually `1` because of exponential cost of higher values.
    ///
    /// # Panics
    ///
    /// The funcion panics in const context and debug builds if `bytes_to_grind` is higher than 62.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const fn ground_p2wpkh(bytes_to_grind: usize) -> Self {
        // Written to trigger const/debug panic for unreasonably high values.
        let der_signature_size = 10 + (62 - bytes_to_grind);
        InputWeightPrediction::from_slice(0, &[der_signature_size, 33])
    }

    /// Input weight prediction corresponding to spending of a P2PKH output using [signature
    /// grinding], and a compressed public key.
    ///
    /// If the input in your transaction uses compressed P2PKH and you use signature grinding you
    /// can use this instead of [`InputWeightPrediction::new`]. See
    /// [`P2PKH_COMPRESSED_MAX`](Self::P2PKH_COMPRESSED_MAX) if you don't use signature grinding.
    ///
    /// Note: `bytes_to_grind` is usually `1` because of exponential cost of higher values.
    ///
    /// # Panics
    ///
    /// The funcion panics in const context and debug builds if `bytes_to_grind` is higher than 62.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const fn ground_p2pkh_compressed(bytes_to_grind: usize) -> Self {
        // Written to trigger const/debug panic for unreasonably high values.
        let der_signature_size = 10 + (62 - bytes_to_grind);

        InputWeightPrediction::from_slice(2 + 33 + der_signature_size, &[])
    }

    /// Computes the prediction for a single input.
    pub fn new<T>(input_script_len: usize, witness_element_lengths: T) -> Self
    where
        T: IntoIterator,
        T::Item: Borrow<usize>,
    {
        let (count, total_size) =
            witness_element_lengths.into_iter().fold((0, 0), |(count, total_size), elem_len| {
                let elem_len = *elem_len.borrow();
                let elem_size = elem_len + VarInt(elem_len as u64).size();
                (count + 1, total_size + elem_size)
            });
        let witness_size = if count > 0 { total_size + VarInt(count as u64).size() } else { 0 };
        let script_size = input_script_len + VarInt(input_script_len as u64).size();

        InputWeightPrediction { script_size, witness_size }
    }

    /// Computes the prediction for a single input in `const` context.
    ///
    /// This is a `const` version of [`new`](Self::new) which only allows slices due to current Rust
    /// limitations around `const fn`. Because of these limitations it may be less efficient than
    /// `new` and thus is intended to be only used in `const` context.
    pub const fn from_slice(input_script_len: usize, witness_element_lengths: &[usize]) -> Self {
        let mut i = 0;
        let mut total_size = 0;
        // for loops not supported in const fn
        while i < witness_element_lengths.len() {
            let elem_len = witness_element_lengths[i];
            let elem_size = elem_len + VarInt(elem_len as u64).size();
            total_size += elem_size;
            i += 1;
        }
        let witness_size = if !witness_element_lengths.is_empty() {
            total_size + VarInt(witness_element_lengths.len() as u64).size()
        } else {
            0
        };
        let script_size = input_script_len + VarInt(input_script_len as u64).size();

        InputWeightPrediction { script_size, witness_size }
    }

    /// Tallies the total weight added to a transaction by an input with this weight prediction,
    /// not counting potential witness flag bytes or the witness count varint.
    pub const fn weight(&self) -> Weight {
        Weight::from_wu_usize(self.script_size * 4 + self.witness_size)
    }
}
