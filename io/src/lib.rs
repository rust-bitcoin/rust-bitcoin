//! Rust-Bitcoin IO Library
//!
//! Because the core `std::io` module is not yet exposed in `no-std` Rust, building `no-std`
//! applications which require reading and writing objects via standard traits is not generally
//! possible. While there is ongoing work to improve this situation, this module is not likely to
//! be available for applications with broad rustc version support for some time.
//!
//! Thus, this library exists to export a minmal version of `std::io`'s traits which `no-std`
//! applications may need. With the `std` feature, these traits are also implemented for the
//! `std::io` traits, allowing standard objects to be used wherever the traits from this crate are
//! required.
//!
//! This traits are not one-for-one drop-ins, but are as close as possible while still implementing
//! `std::io`'s traits without unnecessary complexity.
//!
//! Further, with the `core2` feature, if the `std` feature is not set, the crate traits will be
//! implemented for `core2`'s `io` traits as well.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), not(feature = "core2")))]
compile_error!("At least one of std or core2 must be enabled");

#[cfg(feature = "std")]
pub use std::error;
#[cfg(not(feature = "std"))]
pub use core2::error;

#[cfg(any(feature = "alloc", feature = "std"))]
extern crate alloc;

/// Standard I/O stream definitions which are API-equivalent to `std`'s `io` module. See
/// [`std::io`] for more info.
pub mod io {
    #[cfg(all(not(feature = "std"), not(feature = "core2")))]
    compile_error!("At least one of std or core2 must be enabled");

    #[cfg(feature = "std")]
    pub use std::io::{Read, Write, sink, Cursor, Take, Error, ErrorKind, Result};

    #[cfg(not(feature = "std"))]
    pub use core2::io::{Read, Write, Cursor, Take, Error, ErrorKind, Result};


}
