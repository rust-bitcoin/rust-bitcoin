// SPDX-License-Identifier: CC0-1.0

//! The `WitnessMerkleNode` type.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
#[cfg(feature = "hex")]
use hex::FromHex as _;

/// A hash corresponding to the Merkle tree root for witness data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessMerkleNode(sha256d::Hash);

// The new hash wrapper type.
type HashType = WitnessMerkleNode;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");
