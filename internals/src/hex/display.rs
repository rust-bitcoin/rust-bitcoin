//! Helpers for displaying bytes as hex strings.
//!
//! This module provides a trait for displaying things as hex as well as an implementation for
//! `&[u8]`.

use core::fmt;
#[cfg(feature = "alloc")]
use crate::prelude::*;
use super::buf_encoder::{BufEncoder, OutBytes};
use super::Case;

/// Extension trait for types that can be displayed as hex.
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
    type Display: fmt::Display;

    /// Display `Self` as a continuous sequence of ASCII hex chars.
    fn display_hex(self, case: Case) -> Self::Display;

    /// Shorthand for `display_hex(Case::Lower)`.
    ///
    /// Avoids the requirement to import the `Case` type.
    fn display_lower_hex(self) -> Self::Display {
        self.display_hex(Case::Lower)
    }

    /// Shorthand for `display_hex(Case::Upper)`.
    ///
    /// Avoids the requirement to import the `Case` type.
    fn display_upper_hex(self) -> Self::Display {
        self.display_hex(Case::Upper)
    }

    /// Create a lower-hex-encoded string.
    ///
    /// A shorthand for `to_hex_string(Case::Lower)`, so that `Case` doesn't need to be imported.
    ///
    /// This may be faster than `.display_hex().to_string()` because it uses `reserve_suggestion`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_lower_hex_string(self) -> String {
        self.to_hex_string(Case::Lower)
    }

    /// Create an upper-hex-encoded string.
    ///
    /// A shorthand for `to_hex_string(Case::Upper)`, so that `Case` doesn't need to be imported.
    ///
    /// This may be faster than `.display_hex().to_string()` because it uses `reserve_suggestion`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_upper_hex_string(self) -> String {
        self.to_hex_string(Case::Upper)
    }

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
    /// This may be faster than `write!(string, "{}", self.display_hex())` because it uses
    /// `reserve_sugggestion`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn append_hex_to_string(self, case: Case, string: &mut String) {
        use fmt::Write;

        string.reserve(self.hex_reserve_suggestion());
        write!(string, "{}", self.display_hex(case)).unwrap_or_else(|_| {
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
    fn hex_reserve_suggestion(self) -> usize {
        0
    }
}

mod sealed {
    /// Trait marking a shared reference.
    pub trait IsRef: Copy {
    }

    impl<T: ?Sized> IsRef for &'_ T {
    }
}

impl<'a> DisplayHex for &'a [u8] {
    type Display = DisplayByteSlice<'a>;

    #[inline]
    fn display_hex(self, case: Case) -> Self::Display {
        DisplayByteSlice {
            bytes: self,
            case,
        }
    }

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
/// Created by [`<&[u8] as DisplayHex>::display_hex`](DisplayHex::display_hex).
pub struct DisplayByteSlice<'a> {
    bytes: &'a [u8],
    case: Case,
}

impl<'a> fmt::Display for DisplayByteSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 1024];
        let mut encoder = super::BufEncoder::new(&mut buf);

        let mut chunks = self.bytes.chunks_exact(512);
        for chunk in &mut chunks {
            encoder.put_bytes(chunk, self.case);
            f.write_str(encoder.as_str())?;
            encoder.clear();
        }
        encoder.put_bytes(chunks.remainder(), self.case);
        f.write_str(encoder.as_str())
    }
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
    ($formatter:expr, $len:expr, $bytes:expr, $case:expr) => {
        {
            // statically check $len
            #[allow(deprecated)]
            const _: () = [()][($len > usize::max_value() / 2) as usize];
            assert_eq!($bytes.len(), $len);
            let mut buf = [0u8; $len * 2];
            let buf = $crate::hex::buf_encoder::AsOutBytes::as_mut_out_bytes(&mut buf);
            $crate::hex::display::fmt_hex_exact_fn($formatter, buf, $bytes, $case)
        }
    }
}

// Implementation detail of `write_hex_exact` macro to de-duplicate the code
#[doc(hidden)]
#[inline]
pub fn fmt_hex_exact_fn(f: &mut fmt::Formatter, buf: &mut OutBytes, bytes: &[u8], case: Case) -> fmt::Result {
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
        fn empty() {
            check_encoding(b"");
        }

        #[test]
        fn single() {
            check_encoding(b"*");
        }

        #[test]
        fn two() {
            check_encoding(b"*x");
        }

        #[test]
        fn just_below_boundary() {
            check_encoding(&[42; 512]);
        }

        #[test]
        fn just_above_boundary() {
            check_encoding(&[42; 513]);
        }

        #[test]
        fn just_above_double_boundary() {
            check_encoding(&[42; 1025]);
        }

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
