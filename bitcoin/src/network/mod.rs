// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network support.
//!
//! This module defines support for (de)serialization and network transport
//! of Bitcoin data and network messages.
//!

pub mod constants;

#[cfg(feature = "std")]
pub mod address;
#[cfg(feature = "std")]
pub use self::address::Address;
#[cfg(feature = "std")]
pub mod message;
#[cfg(feature = "std")]
pub mod message_blockdata;
#[cfg(feature = "std")]
pub mod message_bloom;
#[cfg(feature = "std")]
pub mod message_compact_blocks;
#[cfg(feature = "std")]
pub mod message_filter;
#[cfg(feature = "std")]
pub mod message_network;

pub use self::constants::Magic;
