// SPDX-License-Identifier: CC0-1.0

//! The [`Ntxid`] type.

#[cfg(feature = "hex")]
use core::{fmt, str};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;

/// A "normalized TXID".
///
/// Computed on a transaction that has had the signatures removed.
///
/// This type is needed only for legacy (pre-Segwit or P2SH-wrapped segwit version 0)
/// applications. Computing it clears the `script_sig` and `witness` fields of each input. The
/// `script_sig` in Segwit transactions is already empty, so for Segwit transactions the ntxid
/// will be equal to the txid, and you should simply use the latter.
///
/// This gives a way to identify a transaction that is "the same" as another in the sense of
/// having the same inputs and outputs.
///
/// A coinbase `script_sig` is not a signature and may contain a BIP-34 height commitment, so
/// for a coinbase transaction the ntxid is equal to the txid.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ntxid(sha256d::Hash);

super::impl_debug!(Ntxid);

// The new hash wrapper type.
type HashType = Ntxid;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");
