// SPDX-License-Identifier: CC0-1.0

//! The `Txid` type.
//!
//! In order to print and parse txids enable the "hex" feature.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
#[cfg(feature = "hex")]
use hex::FromHex as _;

#[cfg(doc)]
use crate::OutPoint;

/// A bitcoin transaction hash/transaction ID.
///
/// For compatibility with the existing Bitcoin infrastructure and historical and current
/// versions of the Bitcoin Core software itself, this and other [`sha256d::Hash`] types, are
/// serialized in reverse byte order when converted to a hex string via [`std::fmt::Display`]
/// trait operations.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Txid(sha256d::Hash);

impl Txid {
    /// The `Txid` used in a coinbase prevout.
    ///
    /// This is used as the "txid" of the dummy input of a coinbase transaction. This is not a real
    /// TXID and should not be used in any other contexts. See [`OutPoint::COINBASE_PREVOUT`].
    pub const COINBASE_PREVOUT: Self = Self::from_byte_array([0; 32]);
}

// The new hash wrapper type.
type HashType = Txid;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");
