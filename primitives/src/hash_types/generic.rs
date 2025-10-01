// SPDX-License-Identifier: CC0-1.0

// NOTE: This is not a normal module.
//
// Generic implementation of hash wrapper types.
//
// File is included in other files using `include!` allowing us to
// follow the DRY principle without using macros.

const LEN: usize = <Inner as hashes::Hash>::LEN;
const REVERSE: bool =  <Inner as hashes::Hash>::DISPLAY_BACKWARD;

impl HashType {
    /// Constructs a new type from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; LEN]) -> Self {
        Self(Inner::from_byte_array(bytes))
    }

    /// Returns the underlying byte array.
    pub const fn to_byte_array(self) -> [u8; LEN] { self.0.to_byte_array() }

    /// Returns a reference to the underlying byte array.
    pub const fn as_byte_array(&self) -> &[u8; LEN] { self.0.as_byte_array() }
}

#[cfg(feature = "serde")]
super::impl_serde!(HashType, LEN);
super::impl_bytelike_traits!(HashType, LEN);

#[cfg(feature = "hex")]
impl core::fmt::LowerHex for HashType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let case = hex::Case::Lower;

        if REVERSE {
            let bytes = core::borrow::Borrow::<[u8]>::borrow(self).iter().rev();
            hex::fmt_hex_exact!(f, LEN, bytes, case)
        } else {
            let bytes = core::borrow::Borrow::<[u8]>::borrow(self).iter();
            hex::fmt_hex_exact!(f, LEN, bytes, case)
        }
    }
}
#[cfg(feature = "hex")]
impl core::fmt::UpperHex for HashType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let case = hex::Case::Upper;

        if REVERSE {
            let bytes = core::borrow::Borrow::<[u8]>::borrow(self).iter().rev();
            hex::fmt_hex_exact!(f, LEN, bytes, case)
        } else {
            let bytes = core::borrow::Borrow::<[u8]>::borrow(self).iter();
            hex::fmt_hex_exact!(f, LEN, bytes, case)
        }
    }
}
#[cfg(feature = "hex")]
impl core::fmt::Display for HashType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}
#[cfg(feature = "hex")]
impl str::FromStr for HashType {
    type Err = hex::HexToArrayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = <[u8; LEN]>::from_hex(s)?;

        if REVERSE {
            bytes.reverse();
        }
        Ok(Self::from_byte_array(bytes))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for HashType {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = u.arbitrary()?;
        Ok(HashType::from_byte_array(arbitrary_bytes))
    }
}
