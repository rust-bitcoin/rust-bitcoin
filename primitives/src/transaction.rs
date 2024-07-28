// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transactions.

use core::fmt;

use hashes::sha256d;
use internals::write_err;
use units::parse;

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
    /// The "all zeros" TXID.
    ///
    /// This is used as the "txid" of the dummy input of a coinbase transaction. It is
    /// not a real TXID and should not be used in other contexts.
    pub fn all_zeros() -> Self { Self::from_byte_array([0; 32]) }
}

impl Wtxid {
    /// The "all zeros" wTXID.
    ///
    /// This is used as the wTXID for the coinbase transaction when constructing blocks,
    /// since the coinbase transaction contains a commitment to all transactions' wTXIDs
    /// but naturally cannot commit to its own. It is not a real wTXID and should not be
    /// used in other contexts.
    pub fn all_zeros() -> Self { Self::from_byte_array([0; 32]) }
}

/// Trait that abstracts over a transaction identifier i.e., `Txid` and `Wtxid`.
pub trait TxIdentifier: sealed::Sealed + AsRef<[u8]> {}

impl TxIdentifier for Txid {}
impl TxIdentifier for Wtxid {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Txid {}
    impl Sealed for super::Wtxid {}
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
    /// use bitcoin::constants::genesis_block;
    /// use bitcoin::{params, Network};
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
