// SPDX-License-Identifier: CC0-1.0

//! Example: Parse and display a Rune string (Rune protocol placeholder)
//!
//! This is a minimal example for parsing and displaying a Rune string.
//! The Rune protocol is not natively supported in rust-bitcoin as of June 2024.
//! This script demonstrates a basic parser for a hypothetical Rune string format.

use std::env;

/// A simple struct representing a Rune (placeholder for actual protocol fields)
#[derive(Debug)]
struct Rune {
    name: String,
    amount: u64,
}

impl Rune {
    /// Parse a Rune string of the form "NAME:AMOUNT"
    fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let name = parts[0].to_string();
        let amount = parts[1].parse::<u64>().ok()?;
        Some(Rune { name, amount })
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <RUNE_STRING>", args[0]);
        eprintln!("Example: {} FOO:1000", args[0]);
        std::process::exit(1);
    }
    let rune_str = &args[1];
    match Rune::parse(rune_str) {
        Some(rune) => {
            println!("Parsed Rune:");
            println!("  Name:   {}", rune.name);
            println!("  Amount: {}", rune.amount);
        }
        None => {
            eprintln!("Failed to parse Rune string: {}", rune_str);
            std::process::exit(1);
        }
    }
} 