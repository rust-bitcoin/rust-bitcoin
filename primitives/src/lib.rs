// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin - primitive types
//!
//! Primitive data types used throughout the [`rust-bitcoin`] ecosystem.
//!
//! If you are using `rust-bitcoin` you do not need to access this crate directly. All items
//! are re-exported in `rust-bitcoin` at the same path.
//!
//! This crate supports `no_std` environments, but many features require the `alloc` feature.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![no_std]
// Coding conventions
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable
#![allow(clippy::uninlined_format_args)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(feature = "hex")]
pub extern crate hex_stable as hex;

// Internal modules
mod hash_types;
#[cfg(feature = "alloc")]
mod opcodes;

// Public modules
pub mod block;
pub mod merkle_tree;
pub mod pow;
#[cfg(feature = "alloc")]
pub mod script;
pub mod transaction;
#[cfg(feature = "alloc")]
pub mod witness;

// Re-exports from units module
#[doc(inline)]
pub use units::{
    amount::{self, Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::{self, FeeRate},
    locktime::{self, absolute, relative},
    parse_int,
    result::{self, NumOpResult},
    sequence::{self, Sequence},
    time::{self, BlockTime, BlockTimeDecoder, BlockTimeDecoderError},
    weight::{self, Weight},
};

#[deprecated(since = "TBD", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

// Conditional re-exports
#[doc(inline)]
#[cfg(feature = "alloc")]
pub use self::{
    block::{
        Block, Checked as BlockChecked, Unchecked as BlockUnchecked, Validation as BlockValidation,
    },
    script::{
        RedeemScript, RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf, ScriptSig, ScriptSigBuf,
        TapScript, TapScriptBuf, WitnessScript, WitnessScriptBuf,
    },
    transaction::{Transaction, TxIn, TxOut},
    witness::Witness,
};

// Always available re-exports
#[doc(inline)]
pub use self::{
    block::{BlockHash, Header as BlockHeader, Version as BlockVersion, WitnessCommitment},
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    pow::CompactTarget,
    transaction::{Ntxid, OutPoint, Txid, Version as TransactionVersion, Wtxid},
};

// Internal prelude module
#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(feature = "alloc")]
    pub use alloc::{
        borrow::{Borrow, BorrowMut, Cow, ToOwned},
        boxed::Box,
        collections::{BTreeMap, BTreeSet, BinaryHeap, btree_map},
        rc,
        slice,
        string::{String, ToString},
        vec::Vec,
    };

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    pub use alloc::sync;

    // Core prelude for no_std compatibility
    pub use core::prelude::rust_2021::*;
}

// Internal exports for macros and derive
#[doc(hidden)]
pub mod _export {
    /// Re-export of core primitives for macro use
    pub mod _core {
        pub use core::*;
    }
    
    /// Common traits for internal use
    pub mod _traits {
        pub use core::fmt;
        #[cfg(feature = "alloc")]
        pub use alloc::string::ToString;
    }
}
