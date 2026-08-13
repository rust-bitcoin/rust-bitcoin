//! Parse an [`Amount`] from a string and format it in different denominations.

use bitcoin_units::{amount::Denomination, Amount};

fn main() -> Result<(), bitcoin_units::amount::ParseError> {
    let amount = "0.1 BTC".parse::<Amount>()?;
    assert_eq!(amount.to_sat(), 10_000_000);

    assert_eq!(amount.to_string_in(Denomination::Bitcoin), "0.1");
    assert_eq!(amount.to_string_with_denomination(Denomination::Satoshi), "10000000 sat");

    println!("{amount}");
    Ok(())
}
