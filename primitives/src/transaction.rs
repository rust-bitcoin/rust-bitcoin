// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transactions.

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

/// Trait that abstracts over a transaction identifier i.e., `Txid` and `Wtxid`.
pub trait TxIdentifier: sealed::Sealed + AsRef<[u8]> {}

impl TxIdentifier for Txid {}
impl TxIdentifier for Wtxid {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Txid {}
    impl Sealed for super::Wtxid {}
}
