// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin - primitive types
//!
//! Primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! If you are using `rust-bitcoin` then you do not need to access this crate directly. Everything
//! here is re-exported in `rust-bitcoin` at the same path.
//!
//! This crate can be used in a no-std environment but a lot of the functionality requires an
//! allocator i.e., requires the `alloc` feature to be enabled.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![no_std]
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

/// Re-export the `hex-conservative` crate.
#[cfg(feature = "hex")]
pub extern crate hex;

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

#[cfg(not(feature = "hex"))]
use core::fmt;

#[doc(inline)]
#[rustfmt::skip]                // Keep public re-exports separate.
pub use units::{
    amount::{self, Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::{self, FeeRate},
    locktime::{self, absolute, relative},
    parse,
    result::{self, NumOpResult},
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

/// Writes `bytes` as a `hex` string to the formatter.
///
/// For when we cannot rely on having the `hex` feature enabled. Ignores formatter options and just
/// writes with plain old `f.write_char()`.
#[cfg(not(feature = "hex"))]
pub(crate) fn debug_hex(bytes: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";

    for &b in bytes {
        let lower = HEX_TABLE[usize::from(b >> 4)];
        let upper = HEX_TABLE[usize::from(b & 0b00001111)];
        f.write_char(char::from(lower))?;
        f.write_char(char::from(upper))?;
    }
    Ok(())
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
