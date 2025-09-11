// SPDX-License-Identifier: CC0-1.0

//! The `Txid` type.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
#[cfg(feature = "hex")]
use hex::FromHex as _;

/// A "normalized TXID".
///
/// Computed on a transaction that has had the signatures removed.
///
/// This type is needed only for legacy (pre-Segwit or P2SH-wrapped segwit version 0)
/// applications. This method clears the `script_sig` field of each input, which in Segwit
/// transactions is already empty, so for Segwit transactions the ntxid will be equal to the
/// txid, and you should simply use the latter.
///
/// This gives a way to identify a transaction that is "the same" as another in the sense of
/// having the same inputs and outputs.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ntxid(sha256d::Hash);

// The new hash wrapper type.
type HashType = Ntxid;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");
