// SPDX-License-Identifier: CC0-1.0

#[cfg(rust_v_1_65)]
include!("rust_v_1_65/encoder.rs");

#[cfg(not(rust_v_1_65))]
fn main() {}