// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - primitive types.
//!
//! This crate provides primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

#[cfg(bench)]
extern crate test;

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Re-export the `bitcoinconsensus` crate.
#[cfg(feature = "bitcoinconsensus")]
pub extern crate bitcoinconsensus;

/// Re-export the `bech32` crate.
#[cfg(feature = "bech32")]
pub extern crate bech32;

/// Re-export the `base58ck` crate.
#[cfg(feature = "base58")]
pub extern crate base58;

/// Rust implementation of cryptographic hash function algorithms.
pub extern crate hashes;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

/// Re-export the `bitcoin-io` crate.
pub extern crate io;

/// Re-export the `ordered` crate.
#[cfg(feature = "ordered")]
pub extern crate ordered;

/// Re-export the `ordered` crate.
#[cfg(feature = "crypto")]
pub extern crate secp256k1;

#[cfg(feature = "serde")]
#[macro_use]
extern crate actual_serde as serde;

/// Re-export the `bitcoin-units` crate.
pub extern crate units;

#[cfg(test)]
#[macro_use]
mod test_macros;
mod internal_macros;
#[cfg(feature = "serde")]
mod serde_utils;

pub mod block;
pub mod consensus;
pub mod constants;
#[cfg(feature = "crypto")]
mod crypto;
pub mod key;
pub mod locktime;
pub mod merkle_tree;
pub mod network;
pub mod opcodes;
pub mod policy;
pub mod pow;
pub mod script;
pub mod taproot;
pub mod transaction;
pub mod witness;

/// Re-export everything from the `units` crate.
#[doc(inline)]
pub use units::*;

/// Re-export keys and sighash.
#[cfg(feature = "crypto")]
#[doc(inline)]
pub use self::crypto::{
    ecdsa, // `taproot` intentionally not re-expoted, we use `src/taproot.rs` instead.
    key::{
        CompressedPublicKey, Keypair, PrivateKey, PublicKey, TapTweak, TweakedPublicKey,
        UntweakedPublicKey, XOnlyPublicKey,
    },
    sighash::{self, LegacySighash, SegwitV0Sighash, SighashCache, TapSighash, TapSighashTag},
};
/// Re-export types/modules for typical usage.
///
/// Most users should be able to just grab everything straight from the `primitives` crate root.
/// Only niche users should need to dig into the exact submodules.
#[doc(inline)]
pub use self::{
    amount::{Amount, Denomination, SignedAmount},
    block::{Block, BlockHash, WitnessCommitment},
    consensus::{params, VarInt},
    key::{PubkeyHash, WPubkeyHash},
    locktime::{absolute, relative},
    merkle_tree::{MerkleBlock, TxMerkleNode, WitnessMerkleNode},
    network::{Network, NetworkKind},
    opcodes::Opcode,
    pow::{CompactTarget, Target, Work},
    script::witness_program::{self, WitnessProgram},
    script::witness_version::{self, WitnessVersion},
    script::{Script, ScriptBuf, ScriptHash, WScriptHash},
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
    transaction::{OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Wtxid},
    witness::Witness,
};

pub mod amount {
    //! Bitcoin amounts.
    //!
    //! This module mainly introduces the [`Amount`] and [`SignedAmount`] types.
    //! We refer to the documentation on the types for more information.

    use io::{BufRead, Write};

    use crate::consensus::{encode, Decodable, Encodable};

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[doc(inline)]
    pub use units::amount::*;

    impl Decodable for Amount {
        #[inline]
        fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
            Ok(Amount::from_sat(Decodable::consensus_decode(r)?))
        }
    }

    impl Encodable for Amount {
        #[inline]
        fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
            self.to_sat().consensus_encode(w)
        }
    }
}

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, format, slice, rc};

    #[cfg(all(not(feature = "std"), not(test), any(not(rust_v_1_60), target_has_atomic = "ptr")))]
    pub use alloc::sync;

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, format, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    pub use hex::DisplayHex;
}
