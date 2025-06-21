// SPDX-License-Identifier: CC0-1.0

//! Do basic regression tests on the `Display` and `FromStr` impls.

use bitcoin_units::amount::Denomination;
use bitcoin_units::locktime::{absolute, relative};
use bitcoin_units::{Amount, BlockHeight, BlockInterval, SignedAmount, Weight};

macro_rules! check {
    ($($test_name:ident, $ty:path, $val:path, $str:literal);* $(;)?) => {
        $(
            #[test]
            fn $test_name() {
                let got = format!("{}", $val);
                assert_eq!(got, $str);

                let got = $str.parse::<$ty>().unwrap();
                assert_eq!(got, $val)
            }
        )*
    }
}

check! {
    amount_unsigned_one_sat, Amount, Amount::ONE_SAT, "0.00000001 BTC";
    amount_unsigned_max_money, Amount, Amount::MAX, "21000000 BTC";

    denomination_btc, Denomination, Denomination::BTC, "BTC";
    denomination_sat, Denomination, Denomination::SAT, "satoshi";

    amount_signed_one_sat, SignedAmount, SignedAmount::ONE_SAT, "0.00000001 BTC";
    amount_signed_max_money, SignedAmount, SignedAmount::MAX, "21000000 BTC";

    block_height_min, BlockHeight, BlockHeight::MIN, "0";
    block_height_max, BlockHeight, BlockHeight::MAX, "4294967295";

    block_interval_min, BlockInterval, BlockInterval::MIN, "0";
    block_interval_max, BlockInterval, BlockInterval::MAX, "4294967295";

    lock_by_height_absolute_min, absolute::Height, absolute::Height::MIN, "0";
    lock_by_height_absolute_max, absolute::Height, absolute::Height::MAX, "499999999";

    lock_by_height_relative_min, relative::NumberOfBlocks, relative::NumberOfBlocks::MIN, "0";
    lock_by_height_relative_max, relative::NumberOfBlocks, relative::NumberOfBlocks::MAX, "65535";

    lock_by_time_absolute_min, absolute::MedianTimePast, absolute::MedianTimePast::MIN, "500000000";
    lock_by_time_absolute_max, absolute::MedianTimePast, absolute::MedianTimePast::MAX, "4294967295";

    lock_by_time_relative_min, relative::NumberOf512Seconds, relative::NumberOf512Seconds::MIN, "0";
    lock_by_time_relative_max, relative::NumberOf512Seconds, relative::NumberOf512Seconds::MAX, "65535";

    weight_min, Weight, Weight::MIN, "0";
    weight_max, Weight, Weight::MAX, "18446744073709551615";
    weight_max_block, Weight, Weight::MAX_BLOCK, "4000000";
}
