// SPDX-License-Identifier: CC0-1.0

//! # Error
//!
//! Error handling macros and helpers.
//!

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

/// This module is used internally to check that error types implement certain traits.
#[cfg(check_traits)]
pub mod check_traits {
    /// Internal trait to assert that type implements `Send` and `Sync`.
    pub trait AssertSendSync: Send + Sync {}

    /// Internal trait to assert that type implements `Debug` and `Display`.
    pub trait AssertDebugDisplay: core::fmt::Debug + core::fmt::Display {}

    /// Internal trait to assert that type implements `std::error::Error`.
    #[cfg(feature = "std")]
    pub trait AssertError: std::error::Error {}

    /// Checks at compile time that type `$t` implements the traits we require for error types.
    #[macro_export]
    macro_rules! check_pub_error {
        ($ty:ident) => {
            $crate::check_pub_error!($ty, );
        };
        ($ty:ident, $($gen:ident),*) => {
            use internals::error::check_traits::*;

            impl<$($gen),*> AssertSendSync for $ty<$($gen),*> where $($gen: Send + Sync ),* {}
            impl<$($gen),*> AssertDebugDisplay for $ty<$($gen),*> where $($gen: core::fmt::Debug + core::fmt::Display ),* {}

            #[cfg(feature = "std")]
            impl<$($gen),*> AssertError for $ty<$($gen),*> where $($gen: std::error::Error + 'static),* {}
        };
    }
}
