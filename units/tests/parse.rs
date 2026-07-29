// SPDX-License-Identifier: CC0-1.0

//! Tests for parsing integer types from strings.

use bitcoin_units::amount::{Amount, SignedAmount};
use bitcoin_units::locktime::{absolute, relative};
use bitcoin_units::{
    BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, CompactTarget,
    Sequence, Weight,
};

/// Tests `from_hex`/`from_unprefixed_hex` for an integer wrapper type.
///
/// This includes tests for hex parsing errors, but not for non-hex error
/// types.
macro_rules! test_hex_parse {
    ($($test_name:ident, $ty:ty, $hex_bare:literal, $val:expr);*;) => {
        test_hex_parse!(
            $($test_name, $ty, $hex_bare, $val, from_hex, from_unprefixed_hex;)*
        );
    };
    ($($test_name:ident, $ty:ty, $hex_bare:literal, $val:expr, $from_hex:ident, $from_unprefixed_hex:ident);*;) => {
        $(
            mod $test_name {
                use super::*;

                #[test]
                fn from_hex_lower() {
                    let got = <$ty>::$from_hex(concat!("0x", $hex_bare)).unwrap();
                    assert_eq!(got, $val);
                }

                #[test]
                fn from_hex_upper() {
                    let upper = concat!("0x", $hex_bare).to_uppercase();
                    let got = <$ty>::$from_hex(&upper).unwrap();
                    assert_eq!(got, $val);
                }

                #[test]
                fn from_unprefixed_hex_lower() {
                    let got = <$ty>::$from_unprefixed_hex($hex_bare).unwrap();
                    assert_eq!(got, $val);
                }

                #[test]
                fn from_unprefixed_hex_upper() {
                    let upper = $hex_bare.to_uppercase();
                    let got = <$ty>::$from_unprefixed_hex(&upper).unwrap();
                    assert_eq!(got, $val);
                }

                // We can't check the exact error types because
                // they're opaque.

                #[test]
                fn from_hex_missing_prefix_errors() {
                    <$ty>::$from_hex($hex_bare).unwrap_err();
                }

                #[test]
                fn from_unprefixed_hex_has_prefix_errors() {
                    <$ty>::$from_unprefixed_hex(concat!("0x", $hex_bare)).unwrap_err();
                }

                #[test]
                fn from_hex_invalid_char_errors() {
                    <$ty>::$from_hex("0xZZZZ").unwrap_err();
                }

                #[test]
                fn from_unprefixed_hex_invalid_char_errors() {
                    <$ty>::$from_unprefixed_hex("ZZZZ").unwrap_err();
                }

                #[test]
                fn from_hex_empty_errors() {
                    <$ty>::$from_hex("").unwrap_err();
                }

                #[test]
                fn from_unprefixed_hex_empty_errors() {
                    <$ty>::$from_unprefixed_hex("").unwrap_err();
                }
            }
        )*
    }
}

// These types can only fail if the hex is invalid, but the values
// parse correctly for all valid hex values.
test_hex_parse! {
    compact_target, CompactTarget, "010034ab", CompactTarget::from_consensus(0x0100_34ab);
    block_height, BlockHeight, "00000001", BlockHeight::from_u32(1);
    block_height_interval, BlockHeightInterval, "0000000a", BlockHeightInterval::from_u32(10);
    block_mtp, BlockMtp, "12345678", BlockMtp::from_u32(0x1234_5678);
    block_mtp_interval, BlockMtpInterval, "000000ff", BlockMtpInterval::from_u32(255);
    block_time, BlockTime, "5f000000", BlockTime::from_u32(0x5f00_0000);
    weight, Weight, "00000190", Weight::from_wu(400);
    sequence, Sequence, "ffffffff", Sequence::from_consensus(0xFFFF_FFFF);
    number_of_blocks, relative::NumberOfBlocks, "000000ff", relative::NumberOfBlocks::from_height(255);
    number_of_512_seconds, relative::NumberOf512Seconds, "00000001", relative::NumberOf512Seconds::from_512_second_intervals(1);
}

// These types have additional failure modes for valid hex. e.g. an amount > 21M BTC
test_hex_parse! {
    height, absolute::Height, "00000001", absolute::Height::from_u32(1).unwrap();
    median_time_past, absolute::MedianTimePast, "1dcd6500", absolute::MedianTimePast::from_u32(500_000_000).unwrap();
}
test_hex_parse! {
    amount, Amount, "00000001", Amount::from_sat(1).unwrap(), from_sat_hex, from_sat_unprefixed_hex;
    signed_amount, SignedAmount, "00000001", SignedAmount::from_sat(1).unwrap(), from_sat_hex, from_sat_unprefixed_hex;
}

/// Tests that hex parsing rejects out-of-range values for types with constrained ranges.
mod hex_out_of_range {
    use super::*;

    #[test]
    fn height_above_max() {
        // Height max is 499,999,999 (0x1DCD_64FF). 500,000,000 = 0x1DCD_6500 is out of range.
        absolute::Height::from_hex("0x1dcd6500").unwrap_err();
        absolute::Height::from_unprefixed_hex("1dcd6500").unwrap_err();
    }

    #[test]
    fn median_time_past_below_min() {
        // MedianTimePast min is 500,000,000 (0x1DCD_6500). 499,999,999 = 0x1DCD_64FF is below.
        absolute::MedianTimePast::from_hex("0x1dcd64ff").unwrap_err();
        absolute::MedianTimePast::from_unprefixed_hex("1dcd64ff").unwrap_err();
    }

    #[test]
    fn amount_at_max() {
        // Amount::MAX is 21M BTC * 100M sats/BTC = 2,100,000,000,000,000.
        Amount::from_sat_hex("0x775f05a074000").unwrap();
        Amount::from_sat_unprefixed_hex("775f05a074000").unwrap();
    }

    #[test]
    fn amount_above_max() {
        Amount::from_sat_hex("0x775f05a074001").unwrap_err();
        Amount::from_sat_unprefixed_hex("775f05a074001").unwrap_err();
    }

    #[test]
    fn signed_amount_at_max() {
        // Same limit as Amount for positive values.
        SignedAmount::from_sat_hex("0x775f05a074000").unwrap();
        SignedAmount::from_sat_unprefixed_hex("775f05a074000").unwrap();
    }

    #[test]
    fn signed_amount_above_max() {
        SignedAmount::from_sat_hex("0x775f05a074001").unwrap_err();
        SignedAmount::from_sat_unprefixed_hex("775f05a074001").unwrap_err();
    }
}
