// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin - primitive types
//!
//! Primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! This crate can be used in a no-std environment but a lot of the functionality requires an
//! allocator i.e., requires the `alloc` feature to be enabled.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)`instead of enforcing `format!("{x}")`

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(feature = "consensus-encoding")]
extern crate consensus_encoding;

extern crate hashes;

#[cfg(feature = "io")]
extern crate io;

#[doc(hidden)]
pub mod _export {
    /// A re-export of `core::*`.
    pub mod _core {
        pub use core::*;
    }
}

mod internal_macros;
mod opcodes;

pub mod block;
pub mod merkle_tree;
pub mod pow;
#[cfg(feature = "alloc")]
pub mod script;
pub mod transaction;
#[cfg(feature = "alloc")]
pub mod witness;

#[doc(inline)]
pub use units::{
    amount::{self, Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::{self, FeeRate},
    locktime::{self, absolute, relative},
    sequence::{self, Sequence},
    time::{self, BlockTime},
    weight::{self, Weight},
};

#[deprecated(since = "TBD", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

#[doc(inline)]
#[cfg(feature = "alloc")]
pub use self::{
    block::{
        Block, Checked as BlockChecked, Unchecked as BlockUnchecked, Validation as BlockValidation,
    },
    script::{Script, ScriptBuf},
    transaction::{Transaction, TxIn, TxOut},
    witness::Witness,
};
#[doc(inline)]
pub use self::{
    block::{BlockHash, Header as BlockHeader, Version as BlockVersion, WitnessCommitment},
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    pow::CompactTarget,
    transaction::{OutPoint, Txid, Version as TransactionVersion, Wtxid},
};

#[cfg(feature = "consensus-encoding")]
pub(crate) fn consensus_encode_with_size<W: io::Write + ?Sized>(
    data: &[u8],
    w: &mut W,
) -> Result<usize, io::Error> {
    use consensus_encoding::WriteExt as _;

    Ok(w.emit_compact_size(data.len())? + w.emit_slice(data)?)
}

/// Constructs a new `Error::ParseFailed` error.
// This whole variant should go away because of the inner string.
#[cfg(feature = "consensus-encoding")]
pub(crate) fn parse_failed_error(msg: &'static str) -> consensus_encoding::Error {
    consensus_encoding::Error::Parse(consensus_encoding::ParseError::ParseFailed(msg))
}

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(feature = "alloc")]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "alloc")]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    pub use alloc::sync;
}
