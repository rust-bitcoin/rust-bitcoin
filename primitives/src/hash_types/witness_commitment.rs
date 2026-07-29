// SPDX-License-Identifier: CC0-1.0

//! The `WitnessCommitment` type.

#[cfg(feature = "hex")]
use core::{fmt, str};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;

/// A hash corresponding to the witness structure commitment in the coinbase transaction.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessCommitment(sha256d::Hash);

super::impl_debug!(WitnessCommitment);

// The new hash wrapper type.
type HashType = WitnessCommitment;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");
