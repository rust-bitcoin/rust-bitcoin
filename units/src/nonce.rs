// SPDX-License-Identifier: CC0-1.0

//! An unsigned 32 bit nonce value.

use core::fmt;

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
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Nonce({:08x})", self.to_u32())
    }
}

impl fmt::LowerHex for Nonce {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{:#08x}", self.to_u32())
        } else {
            write!(f, "{:08x}", self.to_u32())
        }
    }
}
#[cfg(feature = "alloc")]
internals::impl_to_hex_from_lower_hex!(Nonce, |_: &Nonce| 8);

impl fmt::UpperHex for Nonce {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{:#08X}", self.to_u32())
        } else {
            write!(f, "{:08X}", self.to_u32())
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Nonce {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let t: u32 = u.arbitrary()?;
        Ok(Nonce::from(t))
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn formatting() {
        let nonce = Nonce::from_u32(0xdead_beef);
        assert_eq!(format!("{}", nonce), "deadbeef");
        assert_eq!(format!("{:x}", nonce), "deadbeef");
        assert_eq!(format!("{:X}", nonce), "DEADBEEF");
        assert_eq!(format!("{:#x}", nonce), "0xdeadbeef");
        assert_eq!(format!("{:#X}", nonce), "0xDEADBEEF");
        assert_eq!(format!("{:?}", nonce), "Nonce(deadbeef)");
    }
}
