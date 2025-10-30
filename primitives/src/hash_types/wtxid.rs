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

/// A bitcoin witness transaction ID.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wtxid(sha256d::Hash);

impl Wtxid {
    /// The `Wtxid` of a coinbase transaction.
    ///
    /// This is used as the wTXID for the coinbase transaction when constructing blocks (in the
    /// witness commitment tree) since the coinbase transaction contains a commitment to all
    /// transactions' wTXIDs but naturally cannot commit to its own.
    pub const COINBASE: Self = Self::from_byte_array([0; 32]);
}

// The new hash wrapper type.
type HashType = Wtxid;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");
