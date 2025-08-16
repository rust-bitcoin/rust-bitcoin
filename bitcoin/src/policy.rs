// SPDX-License-Identifier: CC0-1.0

//! Bitcoin policy.
//!
//! This module exposes some constants and functions used in the reference
//! implementation and which, as a consequence, define some network rules.
//!
//! # *Warning*
//! While the constants present in this module are very unlikely to change, they do not define
//! Bitcoin. As such they must not be relied upon as if they were consensus rules.
//!
//! These values were taken from bitcoind v0.21.1 (194b9b8792d9b0798fdb570b79fa51f1d1f5ebaf).

// SPDX-License-Identifier: CC0-1.0

use core::cmp;

use super::constants::{MAX_BLOCK_SIGOPS_COST, WITNESS_SCALE_FACTOR};

/// Maximum weight of a transaction for it to be relayed by most nodes on the network
pub const MAX_STANDARD_TX_WEIGHT: u32 = 400_000;

/// Minimum non-witness size for a standard transaction, set to 65 bytes.
pub const MIN_STANDARD_TX_NONWITNESS_SIZE: u32 = 65;

/// Maximum number of sigops in a standard tx.
pub const MAX_STANDARD_TX_SIGOPS_COST: u32 = MAX_BLOCK_SIGOPS_COST as u32 / 5;

/// The minimum incremental *feerate* (despite the name), in sats per virtual kilobyte for RBF.
pub const DEFAULT_INCREMENTAL_RELAY_FEE: u32 = 1_000;

/// The number of bytes equivalent per signature operation. Affects transaction relay through the
/// virtual size computation.
pub const DEFAULT_BYTES_PER_SIGOP: u32 = 20;

/// The minimum feerate, in sats per kilo-virtualbyte, for defining dust. An output is considered
/// dust if spending it under this feerate would cost more in fee.
pub const DUST_RELAY_TX_FEE: u32 = 3_000;

/// Minimum feerate, in sats per virtual kilobyte, for a transaction to be relayed by most nodes on
/// the network.
pub const DEFAULT_MIN_RELAY_TX_FEE: u32 = 1_000;

/// Default number of hours for an unconfirmed transaction to expire in most of the network nodes'
/// mempools.
pub const DEFAULT_MEMPOOL_EXPIRY: u32 = 336;

// 80 bytes of data, +1 for OP_RETURN, +2 for the pushdata opcodes.
pub(crate) const MAX_OP_RETURN_RELAY: usize = 83;

/// The virtual transaction size, as computed by default by bitcoind node.
pub fn get_virtual_tx_size(weight: i64, n_sigops: i64) -> i64 {
    (cmp::max(weight, n_sigops * DEFAULT_BYTES_PER_SIGOP as i64) + WITNESS_SCALE_FACTOR as i64 - 1)
        / WITNESS_SCALE_FACTOR as i64
}

#[test]
fn vsize_weight_dominates() {
	// When weight >= sigops * DEFAULT_BYTES_PER_SIGOP, vsize = ceil(weight / 4).
	// Example: 4000 weight => 1000 vbytes.
	assert_eq!(get_virtual_tx_size(4000, 1), 1000);
}

#[test]
fn vsize_sigops_dominates() {
	// When sigops * DEFAULT_BYTES_PER_SIGOP > weight, vsize = ceil((sigops * 20) / 4) = ceil(sigops * 5).
	let n_sigops = 250i64;
	let expected = ((n_sigops * DEFAULT_BYTES_PER_SIGOP as i64) + 3) / 4; // ceil division by 4
	assert_eq!(get_virtual_tx_size(1000, n_sigops), expected);
	assert_eq!(expected, 1250);
}

#[test]
fn vsize_zero_values() {
	assert_eq!(get_virtual_tx_size(0, 0), 0);
	// Zero weight but non-zero sigops -> determined purely by sigops.
	let n_sigops = 2i64;
	let expected = ((n_sigops * DEFAULT_BYTES_PER_SIGOP as i64) + 3) / 4;
	assert!(expected > 0);
	assert_eq!(get_virtual_tx_size(0, n_sigops), expected);
} 