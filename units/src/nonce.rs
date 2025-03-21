// SPDX-License-Identifier: CC0-1.0

//! An unsigned 32 bit nonce value.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The bitcoin block nonce.
///
/// Traditionally the block header nonce was modified by miners to change the block hash while
/// searching for a valid block.
///
/// Any `u32` value is valid, no invariant implied or otherwise. 
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Nonce(u32);

impl Nonce {
    /// Constructs a new [`Nonce`] from an unsigned 32 bit integer value.
    #[inline]
    pub const fn from_u32(t: u32) -> Self { Nonce(t) }

    /// Returns the inner `u32` value.
    #[inline]
    pub const fn to_u32(self) -> u32 { self.0 }
}

impl From<u32> for Nonce {
    #[inline]
    fn from(t: u32) -> Self { Self::from_u32(t) }
}

impl From<Nonce> for u32 {
    #[inline]
    fn from(t: Nonce) -> Self { t.to_u32() }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Nonce {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let t: u32 = u.arbitrary()?;
        Ok(Nonce::from(t))
    }
}
