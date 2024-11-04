// SPDX-License-Identifier: CC0-1.0

//! Error code for the `hashes` crate.

use core::fmt;

/// Hex decoding error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexError(pub(crate) HexToArrayErrorInner);

impl HexToArrayError {
    /// Constructs a new invalid char error.
    pub fn new_invalid_char(invalid: u8, pos: usize) -> Self {
        Self(HexToArrayErrorInner::InvalidChar(InvalidCharError {
            invalid, pos,
        }))
    }

    /// Constructs a new invalid length error.
    pub fn new_invalid_length(invalid: usize, expected: usize) -> Self {
        Self(HexToArrayErrorInner::InvalidLength(InvalidLengthError {
            expected, invalid
        }))
    }

    /// Returns the invalid character if this was an invalid char error.
    pub fn invalid_char(&self) -> Option<u8> {
        use HexToArrayErrorInner::*;

        match self.0 {
            InvalidChar(ref e) => Some(e.invalid_char()),
            InvalidLength(_) => None,
        }
    }

    /// Returns the position of the invalid character if this was an invalid char error.
    pub fn invalid_char_pos(&self) -> Option<usize> {
        use HexToArrayErrorInner::*;

        match self.0 {
            InvalidChar(ref e) => Some(e.pos()),
            InvalidLength(_) => None,
        }
    }

    /// Returns (invalid_length, expected_length) if this was an invalid length error.
    pub fn invalid_length(&self) -> Option<(usize, usize)> {
        use HexToArrayErrorInner::*;

        match self.0 {
            InvalidChar(_) => None,
            InvalidLength(ref e) => Some((e.invalid, e.expected)),
        }
    }
}

impl_from_infallible!(HexToArrayError);

/// Hex decoding error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HexToArrayErrorInner {
    /// Non-hexadecimal character.
    InvalidChar(InvalidCharError),
    /// Tried to parse fixed-length hash from a string with the wrong length.
    InvalidLength(InvalidLengthError),
}

impl_from_infallible!(HexToArrayErrorInner);

impl fmt::Display for HexToArrayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HexToArrayErrorInner::*;

        match self.0 {
            InvalidChar(ref e) => write_err!(f, "failed to parse hex digit"; e),
            InvalidLength(ref e) => write_err!(f, "failed to parse hex"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HexToArrayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use HexToArrayErrorInner::*;

        match self.0 {
            InvalidChar(ref e) => Some(e),
            InvalidLength(ref e) => Some(e),
        }
    }
}

/// Invalid hex character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InvalidCharError {
    pub(crate) invalid: u8,
    pub(crate) pos: usize,
}

impl InvalidCharError {
    /// Returns the invalid character byte.
    pub(crate) fn invalid_char(&self) -> u8 { self.invalid }
    /// Returns the position of the invalid character byte.
    pub(crate) fn pos(&self) -> usize { self.pos }
}

impl_from_infallible!(InvalidCharError);

impl fmt::Display for InvalidCharError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid hex char {} at pos {}", self.invalid, self.pos)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCharError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Tried to parse fixed-length hash from a string with the wrong length.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct InvalidLengthError {
    /// The expected length.
    pub(crate) expected: usize,
    /// The invalid length.
    pub(crate) invalid: usize,
}

impl_from_infallible!(InvalidLengthError);

impl fmt::Display for InvalidLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invilad hex string length {} (expected {})", self.invalid, self.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLengthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromSliceError(pub(crate) FromSliceErrorInner);

impl_from_infallible!(FromSliceError);

impl FromSliceError {
    /// Returns the expected slice length.
    pub fn expected_length(&self) -> usize { self.0.expected }

    /// Returns the invalid slice length.
    pub fn invalid_length(&self) -> usize { self.0.got }
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FromSliceErrorInner {
    pub(crate) expected: usize,
    pub(crate) got: usize,
}

impl_from_infallible!(FromSliceErrorInner);

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid slice length {} (expected {})", self.0.got, self.0.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {}

/// Formats error.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            #[cfg(feature = "std")]
            {
                let _ = &$source;   // Prevents clippy warnings.
                write!($writer, $string $(, $args)*)
            }
            #[cfg(not(feature = "std"))]
            {
                write!($writer, concat!($string, ": {}") $(, $args)*, $source)
            }
        }
    }
}
pub(crate) use write_err;

/// Derives `From<core::convert::Infallible>` for the given type.
///
/// Supports types with arbitrary combinations of lifetimes and type parameters.
///
/// Note: Paths are not supported (for ex. impl_from_infallible!(Hello<D: std::fmt::Display>).
///
/// # Examples
///
/// ```rust
/// # #[allow(unused)]
/// # fn main() {
/// # use core::fmt::{Display, Debug};
/// use bitcoin_internals::impl_from_infallible;
///
/// enum AlphaEnum { Item }
/// impl_from_infallible!(AlphaEnum);
///
/// enum BetaEnum<'b> { Item(&'b usize) }
/// impl_from_infallible!(BetaEnum<'b>);
///
/// enum GammaEnum<T> { Item(T) }
/// impl_from_infallible!(GammaEnum<T>);
///
/// enum DeltaEnum<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a> {
///     Item((&'b usize, &'a usize, T, D))
/// }
/// impl_from_infallible!(DeltaEnum<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a>);
///
/// struct AlphaStruct;
/// impl_from_infallible!(AlphaStruct);
///
/// struct BetaStruct<'b>(&'b usize);
/// impl_from_infallible!(BetaStruct<'b>);
///
/// struct GammaStruct<T>(T);
/// impl_from_infallible!(GammaStruct<T>);
///
/// struct DeltaStruct<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a> {
///     hello: &'a T,
///     what: &'b D,
/// }
/// impl_from_infallible!(DeltaStruct<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a>);
/// # }
/// ```
///
/// See <https://stackoverflow.com/a/61189128> for more information about this macro.
macro_rules! impl_from_infallible {
    ( $name:ident $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)? ) => {
        impl $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?
            From<core::convert::Infallible>
        for $name
            $(< $( $lt ),+ >)?
        {
            fn from(never: core::convert::Infallible) -> Self { match never {} }
        }
    }
}
pub(crate) use impl_from_infallible;
