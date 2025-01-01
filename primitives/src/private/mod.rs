// SPDX-License-Identifier: CC0-1.0

//! This directory holds stuff that is general purpose i.e., not specifically related to Bitcoin.
//!
//! In various repositories and crates throughout the `rust-bitcoin` org we copy this directory and
//! then diff against the version in `github.com/rust-bitcoin/rust-bitcoin/internals` to make sure
//! it stays in sync. We do this, as opposed to creating separate crates, because we do not want to
//! maintain a ton of tiny little crates for all of these things.
//!
//! None of these modules should ever be public ensuring that none of the types, macros, or
//! functions defined here are ever public. There are absolutely zero guarantees about the stability
//! of code in this module.

pub(crate) mod impl_parse_str_from_int_infallible;
// pub(crate) mod impl_parse_str;
// pub(crate) mod input_string;
pub(crate) mod write_err;

// Re-export to make `private` import statements more ergonomic.
pub(crate) use impl_parse_str_from_int_infallible::impl_parse_str_from_int_infallible;
// pub(crate) use impl_parse_str::impl_parse_str;
// pub(crate) use input_string::InputString;
pub(crate) use write_err::write_err;
