// SPDX-License-Identifier: CC0-1.0

//! Error code for the `hashes` crate.

use core::fmt;

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
