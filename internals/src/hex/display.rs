//! Helpers for displaying bytes as hex strings.
//!
//! This module provides a trait for displaying things as hex as well as an implementation for
//! `&[u8]`.

use core::borrow::Borrow;
use core::fmt;

use super::buf_encoder::{BufEncoder, OutBytes};
use super::Case;
use crate::hex::buf_encoder::FixedLenBuf;
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// Extension trait for types that can be displayed as hex.
///
/// Types that have a single, obvious text representation being hex should **not** implement this
/// trait and simply implement `Display` instead.
///
/// This trait should be generally implemented for references only. We would prefer to use GAT but
/// that is beyond our MSRV. As a lint we require the `IsRef` trait which is implemented for all
/// references.
pub trait DisplayHex: Copy + sealed::IsRef {
    /// The type providing [`fmt::Display`] implementation.
    ///
    /// This is usually a wrapper type holding a reference to `Self`.
    type Display: fmt::LowerHex + fmt::UpperHex;

    /// Display `Self` as a continuous sequence of ASCII hex chars.
    fn as_hex(self) -> Self::Display;

    /// Create a lower-hex-encoded string.
    ///
    /// A shorthand for `to_hex_string(Case::Lower)`, so that `Case` doesn't need to be imported.
    ///
    /// This may be faster than `.display_hex().to_string()` because it uses `reserve_suggestion`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_lower_hex_string(self) -> String { self.to_hex_string(Case::Lower) }

    /// Create an upper-hex-encoded string.
    ///
    /// A shorthand for `to_hex_string(Case::Upper)`, so that `Case` doesn't need to be imported.
    ///
    /// This may be faster than `.display_hex().to_string()` because it uses `reserve_suggestion`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_upper_hex_string(self) -> String { self.to_hex_string(Case::Upper) }

    /// Create a hex-encoded string.
    ///
    /// This may be faster than `.display_hex().to_string()` because it uses `reserve_suggestion`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_hex_string(self, case: Case) -> String {
        let mut string = String::new();
        self.append_hex_to_string(case, &mut string);
        string
    }

    /// Appends hex-encoded content to an existing `String`.
    ///
    /// This may be faster than `write!(string, "{:x}", self.display_hex())` because it uses
    /// `reserve_sugggestion`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn append_hex_to_string(self, case: Case, string: &mut String) {
        use fmt::Write;

        string.reserve(self.hex_reserve_suggestion());
        match case {
            Case::Lower => write!(string, "{:x}", self.as_hex()),
            Case::Upper => write!(string, "{:X}", self.as_hex()),
        }
        .unwrap_or_else(|_| {
            let name = core::any::type_name::<Self::Display>();
            // We don't expect `std` to ever be buggy, so the bug is most likely in the `Display`
            // impl of `Self::Display`.
            panic!("The implementation of Display for {} returned an error when it shouldn't", name)
        })
    }

    /// Hints how much bytes to reserve when creating a `String`.
    ///
    /// Implementors that know the number of produced bytes upfront should override this.
    /// Defaults to 0.
    ///
    // We prefix the name with `hex_` to avoid potential collision with other methods.
    fn hex_reserve_suggestion(self) -> usize { 0 }
}

mod sealed {
    /// Trait marking a shared reference.
    pub trait IsRef: Copy {}

    impl<T: ?Sized> IsRef for &'_ T {}
}

impl<'a> DisplayHex for &'a [u8] {
    type Display = DisplayByteSlice<'a>;

    #[inline]
    fn as_hex(self) -> Self::Display { DisplayByteSlice { bytes: self } }

    #[inline]
    fn hex_reserve_suggestion(self) -> usize {
        // Since the string wouldn't fit into address space if this overflows (actually even for
        // smaller amounts) it's better to panic right away. It should also give the optimizer
        // better opportunities.
        self.len().checked_mul(2).expect("the string wouldn't fit into address space")
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a> DisplayHex for &'a alloc::vec::Vec<u8> {
    type Display = DisplayByteSlice<'a>;

    #[inline]
    fn as_hex(self) -> Self::Display { DisplayByteSlice { bytes: self } }

    #[inline]
    fn hex_reserve_suggestion(self) -> usize {
        // Since the string wouldn't fit into address space if this overflows (actually even for
        // smaller amounts) it's better to panic right away. It should also give the optimizer
        // better opportunities.
        self.len().checked_mul(2).expect("the string wouldn't fit into address space")
    }
}

/// Displays byte slice as hex.
///
/// Created by [`<&[u8] as DisplayHex>::as_hex`](DisplayHex::as_hex).
pub struct DisplayByteSlice<'a> {
    // pub because we want to keep lengths in sync
    pub(crate) bytes: &'a [u8],
}

impl<'a> DisplayByteSlice<'a> {
    fn display(&self, f: &mut fmt::Formatter, case: Case) -> fmt::Result {
        let mut buf = [0u8; 1024];
        let mut encoder = super::BufEncoder::new(&mut buf);

        let mut chunks = self.bytes.chunks_exact(512);
        for chunk in &mut chunks {
            encoder.put_bytes(chunk, case);
            f.write_str(encoder.as_str())?;
            encoder.clear();
        }
        encoder.put_bytes(chunks.remainder(), case);
        f.write_str(encoder.as_str())
    }
}

impl<'a> fmt::LowerHex for DisplayByteSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.display(f, Case::Lower) }
}

impl<'a> fmt::UpperHex for DisplayByteSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.display(f, Case::Upper) }
}

/// Displays byte array as hex.
///
/// Created by [`<&[u8; LEN] as DisplayHex>::as_hex`](DisplayHex::as_hex).
pub struct DisplayArray<A: Clone + IntoIterator, B: FixedLenBuf>
where
    A::Item: Borrow<u8>,
{
    array: A,
    _buffer_marker: core::marker::PhantomData<B>,
}

impl<A: Clone + IntoIterator, B: FixedLenBuf> DisplayArray<A, B>
where
    A::Item: Borrow<u8>,
{
    /// Creates the wrapper.
    pub fn new(array: A) -> Self { DisplayArray { array, _buffer_marker: Default::default() } }

    fn display(&self, f: &mut fmt::Formatter, case: Case) -> fmt::Result {
        let mut buf = B::uninit();
        let mut encoder = super::BufEncoder::new(&mut buf);
        encoder.put_bytes(self.array.clone(), case);
        f.pad_integral(true, "0x", encoder.as_str())
    }
}

impl<A: Clone + IntoIterator, B: FixedLenBuf> fmt::LowerHex for DisplayArray<A, B>
where
    A::Item: Borrow<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.display(f, Case::Lower) }
}

impl<A: Clone + IntoIterator, B: FixedLenBuf> fmt::UpperHex for DisplayArray<A, B>
where
    A::Item: Borrow<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.display(f, Case::Upper) }
}

/// Format known-length array as hex.
///
/// This supports all formatting options of formatter and may be faster than calling
/// `display_as_hex()` on an arbitrary `&[u8]`. Note that the implementation intentionally keeps
/// leading zeros even when not requested. This is designed to display values such as hashes and
/// keys and removing leading zeros would be confusing.
///
/// ## Parameters
///
/// * `$formatter` - a [`fmt::Formatter`].
/// * `$len` known length of `$bytes`, must be a const expression.
/// * `$bytes` - bytes to be encoded, most likely a reference to an array.
/// * `$case` - value of type [`Case`] determining whether to format as lower or upper case.
///
/// ## Panics
///
/// This macro panics if `$len` is not equal to `$bytes.len()`. It also fails to compile if `$len`
/// is more than half of `usize::MAX`.
#[macro_export]
macro_rules! fmt_hex_exact {
    ($formatter:expr, $len:expr, $bytes:expr, $case:expr) => {{
        // statically check $len
        #[allow(deprecated)]
        const _: () = [()][($len > usize::max_value() / 2) as usize];
        assert_eq!($bytes.len(), $len);
        let mut buf = [0u8; $len * 2];
        let buf = $crate::hex::buf_encoder::AsOutBytes::as_mut_out_bytes(&mut buf);
        $crate::hex::display::fmt_hex_exact_fn($formatter, buf, $bytes, $case)
    }};
}
pub use fmt_hex_exact;

// Implementation detail of `write_hex_exact` macro to de-duplicate the code
#[doc(hidden)]
#[inline]
pub fn fmt_hex_exact_fn<I>(
    f: &mut fmt::Formatter,
    buf: &mut OutBytes,
    bytes: I,
    case: Case,
) -> fmt::Result
where
    I: IntoIterator,
    I::Item: Borrow<u8>,
{
    let mut encoder = BufEncoder::new(buf);
    encoder.put_bytes(bytes, case);
    f.pad_integral(true, "0x", encoder.as_str())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use super::*;

    #[cfg(feature = "alloc")]
    mod alloc {
        use super::*;

        fn check_encoding(bytes: &[u8]) {
            use core::fmt::Write;

            let s1 = bytes.to_lower_hex_string();
            let mut s2 = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                write!(s2, "{:02x}", b).unwrap();
            }
            assert_eq!(s1, s2);
        }

        #[test]
        fn empty() { check_encoding(b""); }

        #[test]
        fn single() { check_encoding(b"*"); }

        #[test]
        fn two() { check_encoding(b"*x"); }

        #[test]
        fn just_below_boundary() { check_encoding(&[42; 512]); }

        #[test]
        fn just_above_boundary() { check_encoding(&[42; 513]); }

        #[test]
        fn just_above_double_boundary() { check_encoding(&[42; 1025]); }

        #[test]
        fn fmt_exact_macro() {
            use crate::alloc::string::ToString;

            struct Dummy([u8; 32]);

            impl fmt::Display for Dummy {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    fmt_hex_exact!(f, 32, &self.0, Case::Lower)
                }
            }

            assert_eq!(Dummy([42; 32]).to_string(), "2a".repeat(32));
        }
    }
}
