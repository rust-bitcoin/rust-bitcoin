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

/// A bitcoin transaction hash/transaction ID.
///
/// For compatibility with the existing Bitcoin infrastructure and historical and current
/// versions of the Bitcoin Core software itself, this and other [`sha256d::Hash`] types, are
/// serialized in reverse byte order when converted to a hex string via [`std::fmt::Display`]
/// trait operations.
///
/// See [`hashes::Hash::DISPLAY_BACKWARD`] for more details.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Txid(sha256d::Hash);

type HashType = Txid;

impl Txid {
    /// The `Txid` used in a coinbase prevout.
    ///
    /// This is used as the "txid" of the dummy input of a coinbase transaction. This is not a real
    /// TXID and should not be used in any other contexts. See [`OutPoint::COINBASE_PREVOUT`].
    ///
    /// [`OutPoint::COINBASE_PREVOUT`]: crate::transaction::OutPoint;
    pub const COINBASE_PREVOUT: Self = Self::from_byte_array([0; 32]);

    /// Constructs a new type from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; LEN]) -> Self {
        Self(sha256d::Hash::from_byte_array(bytes))
    }
}

include!("./generic.rs");

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Txid {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = u.arbitrary()?;
        let t = sha256d::Hash::from_byte_array(arbitrary_bytes);
        Ok(Txid(t))
    }
}
