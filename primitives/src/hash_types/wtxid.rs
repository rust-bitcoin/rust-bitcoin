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

const LEN: usize = 32;
#[cfg(feature = "hex")]
const REVERSE: bool = true;

/// A bitcoin witness transaction ID.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wtxid(sha256d::Hash);

type HashType = Wtxid;

impl Wtxid {
    /// The `Wtxid` of a coinbase transaction.
    ///
    /// This is used as the wTXID for the coinbase transaction when constructing blocks (in the
    /// witness commitment tree) since the coinbase transaction contains a commitment to all
    /// transactions' wTXIDs but naturally cannot commit to its own.
    pub const COINBASE: Self = Self::from_byte_array([0; 32]);

    /// Constructs a new type from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; LEN]) -> Self {
        Self(sha256d::Hash::from_byte_array(bytes))
    }
}

include!("./generic.rs");

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Wtxid {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = u.arbitrary()?;
        let t = sha256d::Hash::from_byte_array(arbitrary_bytes);
        Ok(Wtxid(t))
    }
}
