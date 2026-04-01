// SPDX-License-Identifier: CC0-1.0

//! Demonstrates the use of the Neg trait for `Amount` and `SignedAmount` types.
//!
//! This example shows how to negate amounts, which is useful for representing
//! debits, refunds, or any scenario where you need to flip the sign of a value.

use bitcoin_units::{Amount, SignedAmount};

fn main() {
    // Create a positive amount
    let amount = Amount::from_sat(100_000_000).expect("valid amount"); // 1 BTC
    println!("Original amount: {} ({})", amount, amount.to_sat());

    // Negate the amount (converts to SignedAmount)
    let negated = -amount;
    println!("Negated amount: {} ({})", negated, negated.to_sat());

    // Double negation returns to positive
    let double_neg = -negated;
    println!("Double negation: {} ({})", double_neg, double_neg.to_sat());

    // Example: Calculate change with potential negative result
    let payment = Amount::from_sat(150_000_000).expect("valid amount"); // 1.5 BTC
    let balance = Amount::from_sat(100_000_000).expect("valid amount"); // 1 BTC

    // Using signed subtraction to handle insufficient funds
    let change = balance.signed_sub(payment);
    println!("\nBalance: {}", balance);
    println!("Payment: {}", payment);
    println!("Change (can be negative): {}", change);

    if change.is_negative() {
        println!("Insufficient funds! Short by: {}", -change);
    }

    // Example: Representing debits and credits
    let credit = Amount::from_sat(50_000_000).expect("valid amount"); // 0.5 BTC credit
    let debit = -credit; // 0.5 BTC debit
    println!("\nCredit: {}", credit);
    println!("Debit: {}", debit);

    // Combining operations
    let initial = SignedAmount::from_sat(100_000_000).expect("valid amount");
    let result = initial + debit + SignedAmount::from_sat(25_000_000).expect("valid amount");
    println!("\nInitial: {}", initial);
    println!("After debit and partial credit: {}", result.unwrap());
}
