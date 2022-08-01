// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Library
//!
//! This is a library that supports the Bitcoin network protocol and associated
//! primitives. It is designed for Rust programs built to work with the Bitcoin
//! network.
//!
//! It is also written entirely in Rust to illustrate the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!
//! See README.md for detailed documentation about development and supported
//! environments.
//!
//! ## Available feature flags
//!
//! * `std` - the usual dependency on `std` (default).
//! * `secp-recovery` - enables calculating public key from a signature and message.
//! * `base64` - (dependency), enables encoding of PSBTs and message signatures.
//! * `rand` - (dependency), makes it more convenient to generate random values.
//! * `serde` - (dependency), implements `serde`-based serialization and
//!                 deserialization.
//! * `secp-lowmemory` - optimizations for low-memory devices.
//! * `no-std` - enables additional features required for this crate to be usable
//!              without std. Does **not** disable `std`. Depends on `hashbrown`
//!              and `core2`.
//!

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!(
    "rust-bitcoin currently only supports architectures with pointers wider than 16 bits, let us
    know if you want 16-bit support. Note that we do NOT guarantee that we will implement it!"
);

#[cfg(bench)]
extern crate test;

#[cfg(feature = "no-std")]
#[macro_use]
extern crate alloc;

// Re-export dependencies we control.
pub use bitcoin_hashes as hashes;
pub use secp256k1;
pub use bech32;
#[cfg(feature="bitcoinconsensus")]
pub use bitcoinconsensus;

#[cfg(feature = "serde")]
#[macro_use]
extern crate actual_serde as serde;


#[cfg(test)]
#[macro_use]
mod test_macros;
mod internal_macros;
#[cfg(feature = "serde")]
mod serde_utils;
mod parse;

#[macro_use]
pub mod network;
pub mod blockdata;
pub mod consensus;
pub mod error;
pub mod hash_types;
pub mod policy;
pub mod util;

#[cfg(feature = "std")]
use std::io;

#[cfg(not(feature = "std"))]
use core2::io;

pub use crate::blockdata::block::{Block, BlockHeader};
pub use crate::blockdata::locktime::{self, LockTime, PackedLockTime};
pub use crate::blockdata::script::Script;
#[allow(deprecated)]
pub use crate::blockdata::transaction::SigHashType;
pub use crate::blockdata::transaction::{
    EcdsaSighashType, OutPoint, Sequence, Transaction, TxIn, TxOut,
};
pub use crate::blockdata::witness::Witness;
pub use crate::consensus::encode::VarInt;
pub use crate::hash_types::*;
pub use crate::network::constants::Network;
pub use crate::util::address::{Address, AddressType};
pub use crate::util::amount::{Amount, Denomination, SignedAmount};
pub use crate::util::ecdsa::{self, EcdsaSig, EcdsaSigError};
pub use crate::util::key::{KeyPair, PrivateKey, PublicKey, XOnlyPublicKey};
pub use crate::util::merkleblock::MerkleBlock;
pub use crate::util::schnorr::{self, SchnorrSig, SchnorrSigError};
pub use crate::util::sighash::SchnorrSighashType;
pub use crate::util::{psbt, Error};

#[cfg(not(feature = "std"))]
mod io_extras {
    /// A writer which will move data into the void.
    pub struct Sink {
        _priv: (),
    }

    /// Creates an instance of a writer which will successfully consume all data.
    pub const fn sink() -> Sink { Sink { _priv: () } }

    impl core2::io::Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> { Ok(buf.len()) }

        #[inline]
        fn flush(&mut self) -> core2::io::Result<()> { Ok(()) }
    }
}

#[rustfmt::skip]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Cow, ToOwned}, slice, rc, sync};

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Cow, ToOwned}, slice, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "std")]
    pub use std::io::sink;

    #[cfg(not(feature = "std"))]
    pub use crate::io_extras::sink;

    #[cfg(feature = "hashbrown")]
    pub use hashbrown::HashSet;

    #[cfg(not(feature = "hashbrown"))]
    pub use std::collections::HashSet;
}

#[cfg(bench)]
use bench::EmptyWrite;

#[cfg(bench)]
mod bench {
    use core::fmt::Arguments;

    use crate::io::{IoSlice, Result, Write};

    #[derive(Default, Clone, Debug, PartialEq, Eq)]
    pub struct EmptyWrite;

    impl Write for EmptyWrite {
        fn write(&mut self, buf: &[u8]) -> Result<usize> { Ok(buf.len()) }
        fn write_vectored(&mut self, bufs: &[IoSlice]) -> Result<usize> {
            Ok(bufs.iter().map(|s| s.len()).sum())
        }
        fn flush(&mut self) -> Result<()> { Ok(()) }

        fn write_all(&mut self, _: &[u8]) -> Result<()> { Ok(()) }
        fn write_fmt(&mut self, _: Arguments) -> Result<()> { Ok(()) }
    }
}
