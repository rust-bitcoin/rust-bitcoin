// SPDX-License-Identifier: CC0-1.0

//! # Error
//!
//! Error handling macros and helpers.

#[cfg(not(creusot))]
pub mod input_string;
mod parse_error;

#[cfg(not(creusot))]
pub use input_string::InputString;

#[doc(hidden)]
/// Helper trait for checking whether something implements [`std::error::Error`].
///
/// We use helper trait instead of function to make the compiler handle auto dereferencing.
#[cfg(feature = "std")]
pub trait ErrorExt: std::error::Error + 'static {
    /// Does nothing, just call it
    #[inline(always)]
    fn check_is_actually_error_source(&self) {}
}

#[doc(hidden)]
#[cfg(feature = "std")]
impl<T: std::error::Error + 'static> ErrorExt for T {}

#[doc(hidden)]
/// Indicates whether `T` implements `error::Error`.
///
/// A const is picked when `T` implements the trait, otherwise the lookup falls back to
/// [`NotError::IMPLEMENTS_ERROR`]. This is a variant of dtolnay's [autoref specialization].
///
/// [autoref specialization]: <https://github.com/dtolnay/case-studies/tree/master/autoref-specialization>
pub struct IsError<T: ?Sized>(core::marker::PhantomData<T>);

crate::rust_version::rust_version! {
    if >= 1.81 {
        impl<T: ?Sized + core::error::Error> IsError<T> {
            /// `T` implements `core::error::Error`.
            pub const IMPLEMENTS_ERROR: bool = true;
        }
    } else {
        #[cfg(feature = "std")]
        impl<T: ?Sized + std::error::Error> IsError<T> {
            /// `T` implements `std::error::Error`.
            pub const IMPLEMENTS_ERROR: bool = true;
        }
    }
}

#[doc(hidden)]
/// Fallback of [`IsError`] for types that do not implement `error::Error`.
pub trait NotError {
    /// The type does not implement `error::Error`.
    const IMPLEMENTS_ERROR: bool = false;
}

impl<T: ?Sized> NotError for IsError<T> {}

/// Wraps an `Error` impl to build against whichever `Error` trait is available, if any.
///
/// The macro imports the chosen module as `error`, write the trait as `error::Error`.
///
/// The `Error` trait can only be implemented in the following situations:
/// - `core::error::Error` when building with Rust 1.81 or later.
/// - `std::error::Error` for older compilers, with `std` feature enabled.
///
/// In all other cases, the macro silently ignores whatever is written inside the block.
///
/// # Examples
///
/// ```
/// # use core::fmt;
/// #[derive(Debug)]
/// pub struct InnerError;
/// # impl fmt::Display for InnerError {
/// #     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("inner") }
/// # }
///
/// #[derive(Debug)]
/// pub struct OuterError(InnerError);
/// # impl fmt::Display for OuterError {
/// #     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("outer") }
/// # }
///
/// bitcoin_internals::impl_std_error! {
///     impl error::Error for InnerError {}
/// }
///
/// bitcoin_internals::impl_std_error! {
///     impl error::Error for OuterError {
///         fn source(&self) -> Option<&(dyn error::Error + 'static)> { Some(&self.0) }
///     }
/// }
/// ```
#[macro_export]
macro_rules! impl_std_error {
    ($($item:item)*) => {
        $crate::rust_version::rust_version! {
            if >= 1.81 {
                const _: () = {
                    use core::error;

                    $(
                        #[cfg_attr(docsrs, doc(cfg(any(feature = "std", version("1.81.0")))))]
                        $item
                    )*
                };
            } else {
                #[cfg(feature = "std")]
                const _: () = {
                    use std::error;

                    $(
                        #[cfg_attr(docsrs, doc(cfg(any(feature = "std", version("1.81.0")))))]
                        $item
                    )*
                };
            }
        }
    }
}

/// Formats error.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds. Nothing is appended if `Self` implements `core::error::Error` (Rust 1.81+),
/// where `source()` is available.
///
/// Requirements to use this macro:
/// - It must be called from inside an `impl` block of the error type, because the macro uses
///   `Self` to check whether the error implements `Error`.
/// - `$source` must implement [`std::error::Error`], otherwise it will not compile on std. This is
///   intentional because if it doesn't the macro MUST NOT be used. However this check is very
///   rarely imprecise so if you know what you're doing you can use the unchecked version.
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
                #[allow(unused_imports)]
                use $crate::error::NotError as _;

                if $crate::error::IsError::<Self>::IMPLEMENTS_ERROR {
                    write!($writer, $string $(, $args)*)
                } else {
                    write!($writer, concat!($string, ": {}") $(, $args)*, $source)
                }
            }
        }
    }
}

/// Formats error.
///
/// Unlike [`write_err`] doesn't statically check that `$source` implements `std::error::Error`.
/// This should be used only in rare generic situations. Specifically, in case of a generic
/// `MyError<Error>`, this macro should be used when formatting an error message for the generic
/// type `Error`.
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

#[cfg(test)]
mod tests {
    use core::fmt;
    use core::marker::PhantomData;

    struct Probe<T>(PhantomData<T>);

    trait NotExpanded {
        fn expanded() -> bool { false }
    }

    impl<T> NotExpanded for Probe<T> {}

    #[derive(Debug)]
    struct Leaf;

    impl fmt::Display for Leaf {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("source") }
    }

    impl_std_error! {
        impl error::Error for Leaf {}

        impl Probe<Leaf> {
            fn expanded() -> bool { true }
        }
    }

    #[derive(Debug)]
    struct Wrapper(Leaf);

    impl fmt::Display for Wrapper {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "message"; self.0) }
    }

    impl_std_error! {
        impl error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn error::Error + 'static)> { Some(&self.0) }
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn write_err_appends_source_without_error_impl() {
        use alloc::string::ToString as _;

        /// Implements `Error` only with `std`.
        #[derive(Debug)]
        struct StdOnly(Leaf);

        impl fmt::Display for StdOnly {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write_err!(f, "message"; self.0)
            }
        }

        #[cfg(feature = "std")]
        impl std::error::Error for StdOnly {}

        let expected = if cfg!(feature = "std") { "message" } else { "message: source" };
        assert_eq!(StdOnly(Leaf).to_string(), expected);

        // `Wrapper` implements `Error` on Rust 1.81+, and on older compilers only with `std`.
        let wrapper_is_error = crate::rust_version::rust_version! {
            if >= 1.81 { true } else { cfg!(feature = "std") }
        };
        let expected = if wrapper_is_error { "message" } else { "message: source" };
        assert_eq!(Wrapper(Leaf).to_string(), expected);
    }

    #[test]
    #[cfg(feature = "std")]
    fn impl_std_error_std() {
        use std::error::Error as _;

        assert!(Probe::<Leaf>::expanded());
        assert!(!Probe::<Wrapper>::expanded());
        assert!(Leaf.source().is_none());
        assert!(Wrapper(Leaf).source().unwrap().is::<Leaf>());
    }

    crate::rust_version::rust_version! {
        if >= 1.81 {
            #[test]
            fn impl_std_error_core() {
                use core::error::Error as _;

                assert!(Probe::<Leaf>::expanded());
                assert!(!Probe::<Wrapper>::expanded());
                assert!(Leaf.source().is_none());
                assert!(Wrapper(Leaf).source().unwrap().is::<Leaf>());
            }
        } else {
            #[test]
            #[cfg(not(feature = "std"))]
            fn impl_std_error_none() {
                assert!(!Probe::<Leaf>::expanded());
            }
        }
    }
}
