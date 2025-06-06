// SPDX-License-Identifier: CC0-1.0

//! Transparent non-zero wrappers for hashes and byte arrays

/// Wrapper error for constructing a nonzero wrapper
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Error<Inner> {
    /// No non-zero bytes in slice
    AllZeroBytes,
    /// Transparent variant
    Inner(Inner)
}

impl<Inner> From<Inner> for Error<Inner> {
    fn from(inner: Inner) -> Self {
        Self::Inner(inner)
    }
}

impl<Inner> core::fmt::Display for Error<Inner>
where Inner: core::fmt::Display {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AllZeroBytes => write!(f, "invalid slice (all zeros)"),
            Self::Inner(inner) => inner.fmt(f)
        }
    }
}

#[cfg(feature = "std")]
impl<Inner> std::error::Error for Error<Inner> where Inner: std::error::Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AllZeroBytes => None,
            Self::Inner(inner) => inner.source()
        }
    }
}

/// A transparent wrapper around hashes or byte arrays, that contains at least
/// one non-zero byte.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct NonZero<T>(pub(crate) T);

impl<T> NonZero<T> {
    /// Constructs a non-zero wrapper without checking if the given inner value
    /// contains at least one non-zero byte.
    /// This results in undefined behavior if the inner value does not contain
    /// at least one non-zero byte.
    ///
    /// # Safety
    ///
    /// The inner value must contain at least one non-zero byte.
    #[inline(always)]
    pub fn new_unchecked(inner: T) -> Self { Self(inner) }

    /// Returns the inner value.
    #[inline(always)]
    pub fn get(self) -> T { self.0 }

    /// Convert a reference to the inner type into a reference to the wrapper
    /// type, without checking if the referenced inner value contains at least
    /// one non-zero byte.
    /// 
    /// # Safety
    ///
    /// The referenced inner value must contain at least one non-zero byte.
    #[inline(always)]
    fn wrap_ref_unchecked(inner: &T) -> &Self {
        unsafe {
            let inner_ptr = inner as *const T;
            let wrapper_ptr: *const Self = core::mem::transmute_copy(
                &core::mem::ManuallyDrop::new(inner_ptr)
            );
            &*wrapper_ptr
        }
    }
}

impl<T> NonZero<T> where T: AsRef<[u8]> {
    /// Constructs a non-zero wrapper if the given inner value contains at
    /// least one non-zero byte.
    pub fn new(inner: T) -> Option<Self> {
        if inner.as_ref().iter().any(|b| *b != 0u8) {
            Some(Self(inner))
        } else {
            None
        }
    }
}

impl<T> core::borrow::Borrow<T> for NonZero<T> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T> core::borrow::Borrow<[u8]> for NonZero<T>
where T: core::borrow::Borrow<[u8]> {
    fn borrow(&self) -> &[u8] {
        self.0.borrow()
    }
}

impl<T> core::fmt::Display for NonZero<T> where T: core::fmt::Display {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> core::fmt::LowerHex for NonZero<T> where T: core::fmt::LowerHex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> core::fmt::UpperHex for NonZero<T> where T: core::fmt::UpperHex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> core::ops::Deref for NonZero<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<T> core::str::FromStr for NonZero<T>
where T: core::str::FromStr + AsRef<[u8]> {
    type Err = Error<T::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(T::from_str(s)?).ok_or(Self::Err::AllZeroBytes)
    }
}

impl<T> AsRef<T> for NonZero<T> {
    fn as_ref(&self) -> &T { &self.0 }
}

impl<T> AsRef<[u8]> for NonZero<T> where T: AsRef<[u8]> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "hex")]
impl<T> hex::DisplayHex for &NonZero<T> where T: hex::DisplayHex {
    type Display = T::Display;

    fn as_hex(self) -> Self::Display {
        self.0.as_hex()
    }
}

#[cfg(feature = "hex")]
impl<T> hex::FromHex for NonZero<T> where T: hex::FromHex + AsRef<[u8]> {
    type Error = Error<T::Error>;

    fn from_hex(s: &str) -> Result<Self, Self::Error> {
        Self::new(T::from_hex(s)?).ok_or(Self::Error::AllZeroBytes)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for NonZero<T>
where T: AsRef<[u8]> + serde::Deserialize<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: serde::Deserializer<'de> {
        let inner = T::deserialize(deserializer)?;
        Self::new(inner).ok_or_else(||
            <D::Error as serde::de::Error>::custom(
                "expected at least one non-zero byte"
            )
        )
    }
}

#[cfg(feature = "serde")]
impl<T> serde::Serialize for NonZero<T> where T: serde::Serialize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer {
        self.0.serialize(serializer)
    }
}

impl<T> crate::IsByteArray for NonZero<T> where T: crate::IsByteArray {
    const LEN: usize = T::LEN;
}

impl<T> crate::sealed::IsByteArray for NonZero<T>
where T: crate::sealed::IsByteArray {}

impl<T> crate::Hash for NonZero<T> where T: crate::Hash {
    type Bytes = NonZero<T::Bytes>;

    const LEN: usize = T::LEN;

    const DISPLAY_BACKWARD: bool = T::DISPLAY_BACKWARD;

    #[inline(always)]
    fn from_byte_array(bytes: Self::Bytes) -> Self {
        Self(T::from_byte_array(bytes.0))
    }

    #[inline(always)]
    #[allow(deprecated_in_future)] // Because of `FromSliceError`.
    #[allow(deprecated)]           // Because of `from_slice`.
    fn from_slice(sl: &[u8]) -> Result<Self, crate::FromSliceError> {
        let inner = T::from_slice(sl).map_err(|mut err| {
            if err.0.invalid_all_zeros.is_none() {
                err.0.invalid_all_zeros = Some(sl.iter().all(|b| *b == 0u8));
            }
            err
        })?;
        Self::new(inner).ok_or(
            crate::error::FromSliceError(crate::error::FromSliceErrorInner {
                expected: Self::LEN,
                got: Self::LEN,
                invalid_all_zeros: Some(true),
            })
        )
    }

    #[inline(always)]
    fn as_byte_array(&self) -> &Self::Bytes {
        NonZero::wrap_ref_unchecked(self.0.as_byte_array())
    }

    #[inline(always)]
    fn to_byte_array(self) -> Self::Bytes {
        NonZero(self.0.to_byte_array())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonzero_empty() {
        assert!(NonZero::new([0u8; 0]).is_none())
    }

    #[test]
    fn nonzero_all_zeros() {
        assert!(NonZero::new([0u8; 32]).is_none())
    }

    #[test]
    fn nonzero_ok() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1u8;
        assert!(NonZero::new(bytes).is_some())
    }
}
