// SPDX-License-Identifier: CC0-1.0

//! # Error
//!
//! Error handling macros and helpers.
//!

pub mod input_string;
mod parse_error;

pub use input_string::InputString;

/// Formats error.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds.
#[macro_export]
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

/// Impls std::error::Error for the specified type with appropriate attributes, possibly returning
/// source.
#[macro_export]
macro_rules! impl_std_error {
    // No source available
    ($type:ty) => {
        #[cfg(feature = "std")]
        impl std::error::Error for $type {}
    };
    // Struct with $field as source
    ($type:ty, $field:ident) => {
        #[cfg(feature = "std")]
        impl std::error::Error for $type {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.$field) }
        }
    };
}
