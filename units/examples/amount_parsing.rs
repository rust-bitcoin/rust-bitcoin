// SPDX-License-Identifier: CC0-1.0
//! Demonstrates working with Bitcoin amounts.
//!
//! Bitcoin has a maximum supply of 21 million BTC, enforced by `Amount::MAX`.
//! This limit exists because block rewards halve every 210,000 blocks:
//! 210,000 × (50 + 25 + 12.5 + ...) = 21,000,000 BTC
//!
//! Amounts are stored internally as satoshis (1 BTC = 100,000,000 satoshis).

use bitcoin_units::{amount::Denomination, Amount};

fn main() {
    // The 21 million cap
    let max = Amount::MAX;
    println!("Maximum amount: {} satoshis", max.to_sat());
    println!("Maximum amount: {}", max.display_in(Denomination::Bitcoin).show_denomination());

    // Exceeding the cap returns an error
    let too_big = Amount::from_sat(Amount::MAX.to_sat() + 1);
    println!("Exceeding MAX: {:?}", too_big); // Err(OutOfRangeError)

    // Handling constants - no result handling needed
    let one_btc = Amount::ONE_BTC;
    println!("One BTC = {} satoshis", one_btc.to_sat());

    let zero = Amount::ZERO;
    println!("Zero amount: {} satoshis", zero.to_sat());

    // No result handling for small amounts
    let small = Amount::from_sat_u32(50_000);
    println!("Small Amount = {}", small);

    // Result handling for larger amounts
    let large = Amount::from_sat(100_000_000).expect("valid amount");
    println!("Large Amount = {}", large);

    // Parsing string type to Amount - result handling needed for potential error
    let amount1: Amount = "0.1 BTC".parse().expect("valid amount");
    println!("Amount1 = {}", amount1);
    let amount2 = "100 sat".parse::<Amount>().expect("valid");
    println!("Amount2 = {}", amount2);

    // Formatting with display_in (works without alloc)
    println!("{}", Amount::ONE_BTC.display_in(Denomination::Bitcoin));
    println!("{}", Amount::ONE_SAT.display_in(Denomination::Satoshi));
    println!("{}", Amount::ONE_BTC.display_in(Denomination::Bitcoin).show_denomination());
    println!("{}", Amount::ONE_SAT.display_in(Denomination::Satoshi).show_denomination());

    // to_string_in and to_string_with_denomination require alloc feature
    #[cfg(feature = "alloc")]
    {
        println!("{}", Amount::ONE_BTC.to_string_in(Denomination::Bitcoin));
        println!("{}", Amount::ONE_SAT.to_string_with_denomination(Denomination::Satoshi));
    }

    // Arithmetic operations return NumOpResult
    let a = Amount::from_sat(1000).expect("valid");
    let b = Amount::from_sat(500).expect("valid");

    let sum = a + b; // Returns NumOpResult<Amount>
    println!("Sum = {:?}", sum);

    // Extract the value using .unwrap()
    let sum_amount = (a + b).unwrap();
    println!("Sum amount: {} satoshis", sum_amount.to_sat());

    // Error in case of a negative result
    let small = Amount::from_sat(100).expect("valid");
    let big = Amount::from_sat(1000).expect("valid");
    let difference = small - big;
    println!("Underflow result: {:?}", difference); // Returns error
}
