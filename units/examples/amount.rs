// SPDX-License-Identifier: CC0-1.0

//! Working with Bitcoin amounts.
//!
//! [`Amount`] is a newtype around `u64` representing a value in satoshis, with
//! an enforced maximum of 21 million BTC. This example covers construction,
//! parsing, formatting, and safe arithmetic.

use std::str::FromStr;

use bitcoin_units::amount::{Amount, Denomination};

fn main() {
    the_21_million_cap();
    constructing_amounts();
    parsing_strings();
    formatting_amounts();
    safe_arithmetic();
}

/// `Amount::MAX` is 21,000,000 BTC (2,100,000,000,000,000 satoshis). Any value
/// above this is rejected at construction time. This mirrors the Bitcoin
/// protocol's hard supply cap — there can never be more than 21 million BTC,
/// so any amount claiming to be larger is by definition invalid.
///
/// This catches bugs early: if an intermediate calculation produces a value
/// exceeding 21M BTC, you know something went wrong rather than silently
/// carrying a nonsensical amount through your program.
fn the_21_million_cap() {
    // MAX is exactly 21 million BTC in satoshis.
    assert_eq!(Amount::MAX.to_sat(), 21_000_000 * 100_000_000);

    // Values at or below the cap succeed.
    assert!(Amount::from_sat(Amount::MAX.to_sat()).is_ok());

    // Values above the cap are rejected.
    assert!(Amount::from_sat(Amount::MAX.to_sat() + 1).is_err());

    // The infallible constructor accepts u32 (max ~42.95 BTC, always in range).
    let _small = Amount::from_sat_u32(100_000_000); // 1 BTC
}

/// Amounts can be constructed from satoshis, whole BTC, or floating-point BTC.
fn constructing_amounts() {
    // From satoshis (fallible — checks the 21M cap).
    let a = Amount::from_sat(50_000).unwrap();
    assert_eq!(a.to_sat(), 50_000);

    // From a u32 — infallible since u32::MAX < 21M BTC.
    let b = Amount::from_sat_u32(50_000);
    assert_eq!(a, b);

    // From whole bitcoin.
    let one_btc = Amount::from_int_btc(1u16);
    assert_eq!(one_btc.to_sat(), 100_000_000);

    // Named constants for common values.
    assert_eq!(Amount::ONE_SAT.to_sat(), 1);
    assert_eq!(Amount::ONE_BTC.to_sat(), 100_000_000);
    assert_eq!(Amount::FIFTY_BTC.to_sat(), 5_000_000_000);
}

/// Strings can be parsed in a specific denomination or with an included
/// denomination suffix. The denomination is required when using `FromStr`
/// (except for zero).
fn parsing_strings() {
    // Parse with an explicit denomination.
    let a = Amount::from_str_in("0.1", Denomination::Bitcoin).unwrap();
    assert_eq!(a.to_sat(), 10_000_000);

    // Parse with denomination suffix (used by FromStr).
    let b = Amount::from_str_with_denomination("0.1 BTC").unwrap();
    assert_eq!(a, b);

    // FromStr requires a denomination for non-zero values.
    let c: Amount = "100 satoshi".parse().unwrap();
    assert_eq!(c.to_sat(), 100);

    // Zero is special — no denomination required.
    let zero: Amount = "0".parse().unwrap();
    assert_eq!(zero, Amount::ZERO);

    // Satoshi denomination works too.
    let d = Amount::from_str_in("100000", Denomination::Satoshi).unwrap();
    assert_eq!(d.to_sat(), 100_000);
}

/// Amounts can be formatted in any denomination. The `display_in` method
/// returns a display adapter for use with `format!` / `write!` without
/// allocating. `to_string_in` allocates and returns a `String`.
fn formatting_amounts() {
    let amount = Amount::from_sat(10_000_000).unwrap();

    // Format as BTC (no denomination shown).
    assert_eq!(amount.to_string_in(Denomination::Bitcoin), "0.1");

    // Format with denomination suffix.
    assert_eq!(
        amount.to_string_with_denomination(Denomination::Bitcoin),
        "0.1 BTC"
    );

    // Other denominations.
    assert_eq!(amount.to_string_in(Denomination::Satoshi), "10000000");
    assert_eq!(amount.to_string_in(Denomination::MilliBitcoin), "100");

    // Dynamic display: uses BTC for >= 1 BTC, satoshis otherwise.
    let big = Amount::ONE_BTC;
    assert_eq!(format!("{}", big.display_dynamic()), "1 BTC");
    let small = Amount::from_sat_u32(999);
    assert_eq!(format!("{}", small.display_dynamic()), "999 satoshi");
}

/// Arithmetic operators on `Amount` return `NumOpResult<Amount>`, which
/// catches overflow without panicking. For simple cases where you control
/// all inputs, `unwrap` or `expect` is fine. For untrusted inputs, use
/// `into_result` or pattern matching.
fn safe_arithmetic() {
    let a = Amount::from_sat_u32(1_000_000);
    let b = Amount::from_sat_u32(500_000);

    // Addition returns NumOpResult — unwrap when you know values are safe.
    let sum = (a + b).unwrap();
    assert_eq!(sum.to_sat(), 1_500_000);

    // Subtraction catches underflow (Amount is unsigned).
    let diff = a - b;
    assert!(diff.is_valid());
    assert_eq!(diff.unwrap().to_sat(), 500_000);

    // Subtracting too much produces an error, not a panic.
    let underflow = b - a;
    assert!(underflow.is_error());

    // For untrusted inputs, convert to Result for the ? operator.
    let result: Result<Amount, _> = (a + b).into_result();
    assert!(result.is_ok());
}
