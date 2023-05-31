// SPDX-License-Identifier: CC0-1.0

//! Bitcoin p2p network types.
//!
//! This module defines support for (de)serialization and network transport
//! of Bitcoin data and Bitcoin p2p network messages.

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

/// Version of the protocol as appearing in network message headers.
///
/// This constant is used to signal to other peers which features you support. Increasing it implies
/// that your software also supports every feature prior to this version. Doing so without support
/// may lead to you incorrectly banning other peers or other peers banning you.
///
/// These are the features required for each version:
/// 70016 - Support receiving `wtxidrelay` message between `version` and `verack` message
/// 70015 - Support receiving invalid compact blocks from a peer without banning them
/// 70014 - Support compact block messages `sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn`
/// 70013 - Support `feefilter` message
/// 70012 - Support `sendheaders` message and announce new blocks via headers rather than inv
/// 70011 - Support NODE_BLOOM service flag and don't support bloom filter messages if it is not set
/// 70002 - Support `reject` message
/// 70001 - Support bloom filter messages `filterload`, `filterclear` `filteradd`, `merkleblock` and FILTERED_BLOCK inventory type
/// 60002 - Support `mempool` message
/// 60001 - Support `pong` message and nonce in `ping` message
pub const PROTOCOL_VERSION: u32 = 70001;
