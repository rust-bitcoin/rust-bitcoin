// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin BIP-158 implementation.
//!
//! This crate implements the basic compact block filter defined by [BIP-0158], together with the
//! filter hashes and filter-header chain defined by [BIP-0157]. Compact block filters allow a
//! client to determine whether a block might contain relevant scripts without downloading the
//! entire block. A match is probabilistic: false positives are possible, but false negatives are
//! not when the filter and block hash are correct.
//!
//! [`BasicFilter`] provides the main API.
//!
//! With `alloc`, a filter can be constructed from a checked block with `BasicFilter::from_block`;
//! Without `alloc`, a filter can be parsed from its wire representation with [`BasicFilter::from_bytes`].
//!
//! Use [`BasicFilter::match_any`] or [`BasicFilter::match_all`] to query serialized scriptPubKeys.
//! The block hash passed to these methods must be the hash of the block for which the filter was
//! constructed because BIP-0158 derives the filter's `SipHash` key from it.
//!
//! Basic filters contain the scriptPubKeys of a block's outputs, except empty and `OP_RETURN`
//! outputs, and the scriptPubKeys of the outputs spent by its non-coinbase inputs. Constructing a
//! filter therefore requires access to the previous outputs referenced by the block.
//!
//! # Examples
//!
//! Parses an empty filter and queries it:
//!
//! ```rust
//! use bitcoin_bip158::BasicFilter;
//! use primitives::BlockHash;
//!
//! let filter = BasicFilter::from_bytes(&[0]).expect("an empty filter is valid");
//! let block_hash = BlockHash::from_byte_array([0; 32]);
//!
//! assert!(!filter.match_any(block_hash, [b"script of interest"]));
//! assert_eq!(filter.as_bytes(), &[0]);
//! ```
//!
//! ### Relevant BIPs
//!
//! * [BIP-0157 - Client Side Block Filtering][BIP-0157]
//! * [BIP-0158 - Compact Block Filters for Light Clients][BIP-0158]
//!
//! [BIP-0157]: <https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki>
//! [BIP-0158]: <https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki>

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod filter;
mod hash_types;

pub use self::filter::{
    BasicFilter, BuildError, DecodeError, BASIC_FILTER_M, BASIC_FILTER_P, BASIC_FILTER_TYPE,
};
pub use self::hash_types::{
    FilterHash, FilterHashDecoder, FilterHashDecoderError, FilterHashEncoder, FilterHeader,
    FilterHeaderDecoder, FilterHeaderDecoderError, FilterHeaderEncoder,
};

include!("../include/decoder_newtype.rs"); // decoder_newtype! macro
