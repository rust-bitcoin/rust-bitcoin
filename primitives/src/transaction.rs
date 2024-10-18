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

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
#[cfg(feature = "alloc")]
use internals::write_err;
#[cfg(feature = "alloc")]
use units::parse;

#[cfg(feature = "alloc")]
use crate::script::ScriptBuf;
#[cfg(feature = "alloc")]
use crate::sequence::Sequence;
#[cfg(feature = "alloc")]
use crate::witness::Witness;

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
    parse::int(s).map_err(ParseOutPointError::Vout)
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
internals::impl_from_infallible!(ParseOutPointError);

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
/// Standardness of the inner `i32` is not an invariant because you are free to create transactions
/// of any version, transactions with non-standard version numbers will not be relayed by the
/// Bitcoin network.
///
/// [BIP-68]: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
/// [BIP-431]: https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(pub i32);

impl Version {
    /// The original Bitcoin transaction version (pre-BIP-68).
    pub const ONE: Self = Self(1);

    /// The second Bitcoin transaction version (post-BIP-68).
    pub const TWO: Self = Self(2);

    /// The third Bitcoin transaction version (post-BIP-431).
    pub const THREE: Self = Self(3);
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
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
