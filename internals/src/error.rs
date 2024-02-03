// SPDX-License-Identifier: CC0-1.0

//! # Error
//!
//! Error handling macros and helpers.
//!

pub mod input_string;
mod parse_error;

pub use input_string::InputString;

/// Helper trait for checking whether something implements [`std::error::Error`].
///
/// We use helper trait instead of function to make the compiler handle auto dereferencing.
#[cfg(feature = "std")]
pub trait ErrorExt: std::error::Error + 'static {
    /// Does nothing, just call it
    #[inline(always)]
    fn check_is_actually_error_source(&self) {}
}

#[cfg(feature = "std")]
impl<T: std::error::Error + 'static> ErrorExt for T { }

/// Formats error.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds.
///
/// Note: will not compile on std if $source doesn't implement [`std::error::Error`]. This is
/// intentional because if it doesn't the macro MUST NOT be used. However this check is very rarely
/// imprecise so if you know what you're doing you can use the unchecked version.
#[macro_export]
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            #[cfg(feature = "std")]
            {
                use $crate::error::ErrorExt;

                // Enforces that $source is actually an error.
                //
                // Occasionally people accidentally use write_err! with non-error and it's quite
                // hard to detect otherwise so this gives them compilation error.
                // Also avoids lints saying $source is unused.
                ($source).check_is_actually_error_source();

                write!($writer, $string $(, $args)*)
            }
            #[cfg(not(feature = "std"))]
            {
                write!($writer, concat!($string, ": {}") $(, $args)*, $source)
            }
        }
    }
}

/// Formats error.
///
/// Unlike [`write_err`] doesn't statically check that `$source` implements `std::error::Error`.
/// This should be used only in rare generic situations.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds.
#[macro_export]
macro_rules! write_err_unchecked_source {
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
