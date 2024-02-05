// SPDX-License-Identifier: CC0-1.0

//! Contains error types and other error handling tools.

#[deprecated(since = "TBD", note = "use bitcoin::units::ParseIntError instead")]
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::parse::ParseIntError;
