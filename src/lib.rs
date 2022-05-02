// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

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
//! * `unstable` - enables unstable features for testing.
//! * `rand` - (dependency), makes it more convenient to generate random values.
//! * `use-serde` - (dependency), implements `serde`-based serialization and
//!                 deserialization.
//! * `secp-lowmemory` - optimizations for low-memory devices.
//! * `no-std` - enables additional features required for this crate to be usable
//!              without std. Does **not** disable `std`. Depends on `hashbrown`
//!              and `core2`.
//!

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

// Experimental features we need
#![cfg_attr(all(test, feature = "unstable"), feature(test))]

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
#![deny(broken_intra_doc_links)]

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!("rust-bitcoin currently only supports architectures with pointers wider
                than 16 bits, let us know if you want 16-bit support. Note that we do
                NOT guarantee that we will implement it!");

#[cfg(feature = "no-std")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "no-std")]
extern crate core2;

#[cfg(any(feature = "std", test))]
extern crate core; // for Rust 1.29 and no-std tests

// Re-exported dependencies.
#[macro_use] pub extern crate bitcoin_hashes as hashes;
pub extern crate secp256k1;
pub extern crate bech32;

#[cfg(feature = "no-std")]
extern crate hashbrown;

#[cfg(feature = "base64")]
#[cfg_attr(docsrs, doc(cfg(feature = "base64")))]
pub extern crate base64;

#[cfg(feature="bitcoinconsensus")] extern crate bitcoinconsensus;
#[cfg(feature = "serde")] #[macro_use] extern crate serde;
#[cfg(all(test, feature = "serde"))] extern crate serde_json;
#[cfg(all(test, feature = "serde"))] extern crate serde_test;
#[cfg(all(test, feature = "serde"))] extern crate bincode;
#[cfg(all(test, feature = "unstable"))] extern crate test;

#[cfg(target_pointer_width = "16")]
compile_error!("rust-bitcoin cannot be used on 16-bit architectures");

#[cfg(test)]
#[macro_use]
mod test_macros;
#[macro_use]
mod internal_macros;
#[cfg(feature = "serde")]
mod serde_utils;

#[macro_use]
pub mod network;
pub mod blockdata;
pub mod util;
pub mod consensus;
pub mod hash_types;
pub mod policy;

pub use crate::hash_types::*;
pub use crate::blockdata::block::Block;
pub use crate::blockdata::block::BlockHeader;
pub use crate::blockdata::script::Script;
pub use crate::blockdata::transaction::Transaction;
pub use crate::blockdata::transaction::TxIn;
pub use crate::blockdata::transaction::TxOut;
pub use crate::blockdata::transaction::OutPoint;
pub use crate::blockdata::transaction::EcdsaSighashType;
pub use crate::blockdata::witness::Witness;
pub use crate::consensus::encode::VarInt;
pub use crate::network::constants::Network;
pub use crate::util::Error;
pub use crate::util::address::Address;
pub use crate::util::address::AddressType;
pub use crate::util::amount::Amount;
pub use crate::util::amount::Denomination;
pub use crate::util::amount::SignedAmount;
pub use crate::util::merkleblock::MerkleBlock;
pub use crate::util::sighash::SchnorrSighashType;

pub use crate::util::ecdsa::{self, EcdsaSig, EcdsaSigError};
pub use crate::util::schnorr::{self, SchnorrSig, SchnorrSigError};
pub use crate::util::key::{PrivateKey, PublicKey, XOnlyPublicKey, KeyPair};
pub use crate::util::psbt;
#[allow(deprecated)]
pub use crate::blockdata::transaction::SigHashType;

#[cfg(feature = "std")]
use std::io;
#[cfg(not(feature = "std"))]
use core2::io;

#[cfg(not(feature = "std"))]
mod io_extras {
    /// A writer which will move data into the void.
    pub struct Sink {
        _priv: (),
    }

    /// Creates an instance of a writer which will successfully consume all data.
    pub const fn sink() -> Sink {
        Sink { _priv: () }
    }

    impl core2::io::Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
            Ok(buf.len())
        }

        #[inline]
        fn flush(&mut self) -> core2::io::Result<()> {
            Ok(())
        }
    }
}

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
    pub use io_extras::sink;

    #[cfg(feature = "hashbrown")]
    pub use hashbrown::HashSet;

    #[cfg(not(feature = "hashbrown"))]
    pub use std::collections::HashSet;
}

#[cfg(all(test, feature = "unstable"))] use tests::EmptyWrite;

#[cfg(all(test, feature = "unstable"))]
mod tests {
    use core::fmt::Arguments;
    use io::{IoSlice, Result, Write};

    #[derive(Default, Clone, Debug, PartialEq, Eq)]
    pub struct EmptyWrite;

    impl Write for EmptyWrite {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            Ok(buf.len())
        }
        fn write_vectored(&mut self, bufs: &[IoSlice]) -> Result<usize> {
            Ok(bufs.iter().map(|s| s.len()).sum())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }

        fn write_all(&mut self, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn write_fmt(&mut self, _: Arguments) -> Result<()> {
            Ok(())
        }
    }
}
