// SPDX-License-Identifier: CC0-1.0

//! Working with `NumOpResult` — overflow-safe math for Bitcoin amounts.
//!
//! Bitcoin amounts must never silently overflow: a wrapping addition could turn
//! a large payment into dust. `NumOpResult` is a monadic type (like `Result`)
//! that catches overflow and division-by-zero while still allowing ergonomic
//! chained arithmetic via operator overloading.
//!
//! This example covers:
//! 1. Why `NumOpResult` exists (not just `Result`)
//! 2. Chaining arithmetic: `a + b - c`
//! 3. Inspecting errors: overflow vs. division-by-zero
//! 4. Summing with iterators

use bitcoin_units::{Amount, FeeRate, NumOpResult, Weight};

fn main() {
    why_not_just_result();
    chaining_arithmetic();
    inspecting_errors();
    summing_with_iterators();
}

/// Standard `Result` doesn't implement `Add`, `Sub`, etc. — you'd need to
/// unwrap or match at every step. `NumOpResult` implements the math operators
/// so errors propagate automatically, much like `NaN` in floating point.
///
/// This means `a + b - c` is a single expression, not three match arms.
fn why_not_just_result() {
    let a = Amount::from_sat_u32(100);
    let b = Amount::from_sat_u32(200);
    let c = Amount::from_sat_u32(50);

    // With NumOpResult, chained math just works:
    let result: NumOpResult<Amount> = a + b - c;
    assert_eq!(result.unwrap(), Amount::from_sat_u32(250));

    // Compare what you'd need without it:
    //   let ab = a.checked_add(b).ok_or(err)?;
    //   let abc = ab.checked_sub(c).ok_or(err)?;
    // NumOpResult eliminates that boilerplate.
}

/// Arithmetic operators on `Amount` return `NumOpResult<Amount>`, and
/// `NumOpResult<Amount>` itself implements `Add`, `Sub`, etc. — so you
/// can chain as many operations as you like. If any step overflows, the
/// error propagates through the rest of the chain automatically.
fn chaining_arithmetic() {
    // A realistic scenario: computing change from two UTXOs.
    let utxo_1 = Amount::from_sat_u32(1_000_000); // 0.01 BTC
    let utxo_2 = Amount::from_sat_u32(765_432);

    let spend = Amount::from_sat_u32(1_200_000);
    let fee = Amount::from_sat_u32(100);

    // All four values in one expression — no intermediate unwraps.
    let change = (utxo_1 + utxo_2 - spend - fee).unwrap();
    assert_eq!(change, Amount::from_sat_u32(565_332));

    // If spend exceeds inputs, the subtraction overflows (Amount is unsigned).
    let big_spend = Amount::from_sat_u32(2_000_000);
    let result = utxo_1 + utxo_2 - big_spend - fee;
    assert!(result.is_error());

    // Use `into_result()` to convert to a standard `Result` for `?` operator.
    let as_result: Result<Amount, _> = (utxo_1 + utxo_2 - spend - fee).into_result();
    assert!(as_result.is_ok());
}

/// When a chain fails, you can inspect *which* operation caused the error
/// and whether it was overflow or division-by-zero.
fn inspecting_errors() {
    // Overflow: subtracting more than we have.
    let small = Amount::from_sat_u32(100);
    let big = Amount::from_sat_u32(200);
    let err = (small - big).unwrap_err();

    assert!(err.is_overflow());
    assert!(err.operation().is_subtraction());

    // Division by zero: dividing by a zero fee rate.
    let amount = Amount::from_sat_u32(1000);
    let zero_rate = FeeRate::ZERO;
    let err = (amount / zero_rate).unwrap_err();

    assert!(err.is_div_by_zero());

    // Pattern matching for fine-grained control:
    let fee_budget = Amount::from_sat_u32(500);
    let rate = FeeRate::from_sat_per_vb(1);
    match fee_budget / rate {
        NumOpResult::Valid(weight) => {
            // Maximum transaction weight we can afford.
            assert!(weight.to_wu() > 0);
        }
        NumOpResult::Error(e) if e.is_div_by_zero() => {
            panic!("fee rate should not be zero");
        }
        NumOpResult::Error(_) => {
            panic!("unexpected overflow");
        }
    }
}

/// `NumOpResult<Amount>` implements `Sum`, so you can sum an iterator of
/// results. If any element is an error, the entire sum is an error.
fn summing_with_iterators() {
    let amounts = [
        Amount::from_sat_u32(42),
        Amount::from_sat_u32(1337),
        Amount::from_sat_u32(21),
    ];

    // Map each Amount into a NumOpResult, then sum.
    let total: NumOpResult<Amount> = amounts
        .into_iter()
        .map(NumOpResult::from)
        .sum();
    assert_eq!(total.unwrap(), Amount::from_sat_u32(1400));

    // You can also sum the results of arithmetic directly.
    let fee_rate = FeeRate::from_sat_per_vb(2);
    let weights = [
        Weight::from_vb(100).unwrap(),
        Weight::from_vb(250).unwrap(),
        Weight::from_vb(150).unwrap(),
    ];

    // Calculate fee for each transaction, then sum all fees.
    let total_fees: NumOpResult<Amount> = weights
        .into_iter()
        .map(|w| fee_rate * w)  // Each yields NumOpResult<Amount>
        .sum();
    // (100 + 250 + 150) vB * 2 sat/vB = 1000 sats
    assert_eq!(total_fees.unwrap(), Amount::from_sat_u32(1000));
}
