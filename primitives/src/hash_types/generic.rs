// SPDX-License-Identifier: CC0-1.0

// NOTE: This is not a normal module.
//
// Generic implementation of hash wrapper types.
//
// File is included in other files using `include!` allowing us to
// follow the DRY principle without using macros.

const LEN: usize = <Inner as hashes::Hash>::LEN;
#[cfg(feature = "hex")]
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
impl fmt::LowerHex for HashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

#[cfg(feature = "hex")]
impl fmt::UpperHex for HashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

#[cfg(feature = "hex")]
impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

#[cfg(feature = "hex")]
impl str::FromStr for HashType {
    type Err = hex::DecodeFixedLengthBytesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = crate::hex::decode_to_array(s)?;

        if REVERSE {
            bytes.reverse();
        }
        Ok(Self::from_byte_array(bytes))
    }
}

#[cfg(feature = "hex")]
impl core::convert::TryFrom<&str> for HashType {
    type Error = hex::DecodeFixedLengthBytesError;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as str::FromStr>::from_str(s)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl core::convert::TryFrom<alloc::string::String> for HashType {
    type Error = hex::DecodeFixedLengthBytesError;

    #[inline]
    fn try_from(s: alloc::string::String) -> Result<Self, Self::Error> {
        <Self as str::FromStr>::from_str(&s)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl core::convert::TryFrom<alloc::boxed::Box<str>> for HashType {
    type Error = hex::DecodeFixedLengthBytesError;

    #[inline]
    fn try_from(s: alloc::boxed::Box<str>) -> Result<Self, Self::Error> {
        <Self as str::FromStr>::from_str(&s)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl core::convert::TryFrom<alloc::rc::Rc<str>> for HashType {
    type Error = hex::DecodeFixedLengthBytesError;

    #[inline]
    fn try_from(s: alloc::rc::Rc<str>) -> Result<Self, Self::Error> {
        <Self as str::FromStr>::from_str(&s)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
#[cfg(target_has_atomic = "ptr")]
impl core::convert::TryFrom<alloc::sync::Arc<str>> for HashType {
    type Error = hex::DecodeFixedLengthBytesError;

    #[inline]
    fn try_from(s: alloc::sync::Arc<str>) -> Result<Self, Self::Error> {
        <Self as str::FromStr>::from_str(&s)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for HashType {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = u.arbitrary()?;
        Ok(Self::from_byte_array(arbitrary_bytes))
    }
}
