// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.

use core::fmt;

use hashes::sha256d;

hashes::hash_newtype! {
    /// A bitcoin transaction hash/transaction ID.
    ///
    /// For compatibility with the existing Bitcoin infrastructure and historical and current
    /// versions of the Bitcoin Core software itself, this and other [`sha256d::Hash`] types, are
    /// serialized in reverse byte order when converted to a hex string via [`std::fmt::Display`]
    /// trait operations.
    ///
    /// See [`hashes::Hash::DISPLAY_BACKWARD`] for more details.
    pub struct Txid(sha256d::Hash);

    /// A bitcoin witness transaction ID.
    pub struct Wtxid(sha256d::Hash);
}

impl Txid {
    /// The "all zeros" TXID.
    ///
    /// This is used as the "txid" of the dummy input of a coinbase transaction. It is
    /// not a real TXID and should not be used in other contexts.
    pub fn all_zeros() -> Self { Self::from_byte_array([0; 32]) }
}

impl Wtxid {
    /// The "all zeros" wTXID.
    ///
    /// This is used as the wTXID for the coinbase transaction when constructing blocks,
    /// since the coinbase transaction contains a commitment to all transactions' wTXIDs
    /// but naturally cannot commit to its own. It is not a real wTXID and should not be
    /// used in other contexts.
    pub fn all_zeros() -> Self { Self::from_byte_array([0; 32]) }
}

/// The transaction version.
///
/// Currently, as specified by [BIP-68], only version 1 and 2 are considered standard.
///
/// Standardness of the inner `i32` is not an invariant because you are free to create transactions
/// of any version, transactions with non-standard version numbers will not be relayed by the
/// Bitcoin network.
///
/// [BIP-68]: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(pub i32);

impl Version {
    /// The original Bitcoin transaction version (pre-BIP-68).
    pub const ONE: Self = Self(1);

    /// The second Bitcoin transaction version (post-BIP-68).
    pub const TWO: Self = Self(2);
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}
