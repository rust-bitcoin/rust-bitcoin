// SPDX-License-Identifier: CC0-1.0

//! # Bitcoin Addresses
//!
//! Bitcoin addresses do not appear on chain; rather, they are conventions used by Bitcoin (wallet)
//! software to communicate where coins should be sent and are based on the output type e.g., P2WPKH.
//!
//! This crate can be used in a no-std environment but requires an allocator.
//!
//! ref: <https://sprovoost.nl/2022/11/10/what-is-a-bitcoin-address/>

#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
pub mod witness_program;

#[cfg(feature = "alloc")]
use primitives::script::{Builder, PushBytes, ScriptBuf};
#[cfg(feature = "alloc")]
use primitives::witness_version::WitnessVersion;

/// Generates P2WSH-type of scriptPubkey with a given [`WitnessVersion`] and the program bytes.
/// Does not do any checks on version or program length.
///
/// Convenience method used by `new_p2a`, `new_p2wpkh`, `new_p2wsh`, `new_p2tr`, and `new_p2tr_tweaked`.
#[cfg(feature = "alloc")]
fn new_witness_program_unchecked<T: AsRef<PushBytes>, Tg>(
    version: WitnessVersion,
    program: T,
) -> ScriptBuf<Tg> {
    let program = program.as_ref();
    debug_assert!(program.len() >= 2 && program.len() <= 40);
    // In SegWit v0, the program must be either 20 bytes (P2WPKH) or 32 bytes (P2WSH) long.
    debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
    Builder::new().push_opcode(version.into()).push_slice(program).into_script()
}
