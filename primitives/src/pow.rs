// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.

use core::fmt;

use internals::impl_to_hex_from_lower_hex;

/// Encoding of 256-bit target as 32-bit float.
///
/// This is used to encode a target into the block header. Satoshi made this part of consensus code
/// in the original version of Bitcoin, likely copying an idea from OpenSSL.
///
/// OpenSSL's bignum (BN) type has an encoding, which is even called "compact" as in bitcoin, which
/// is exactly this format.
///
/// # Note on order/equality
///
/// Usage of the ordering and equality traits for this type may be surprising. Converting between
/// `CompactTarget` and `Target` is lossy *in both directions* (there are multiple `CompactTarget`
/// values that map to the same `Target` value). Ordering and equality for this type are defined in
/// terms of the underlying `u32`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// Creates a [`CompactTarget`] from a consensus encoded `u32`.
    pub fn from_consensus(bits: u32) -> Self { Self(bits) }

    /// Returns the consensus encoded `u32` representation of this [`CompactTarget`].
    pub fn to_consensus(self) -> u32 { self.0 }
}

impl fmt::LowerHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}
impl_to_hex_from_lower_hex!(CompactTarget, |compact_target: &CompactTarget| 8 - compact_target
    .0
    .leading_zeros()
    as usize
    / 4);

impl fmt::UpperHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}
