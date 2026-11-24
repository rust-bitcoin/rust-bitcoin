#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::Unstructured;
use bitcoin::parse_int;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

/// Checks `int_from_*` against std's `FromStr`.
macro_rules! check_int {
    ($s:expr, $($ty:ty),*) => {$(
        let expected = $s.parse::<$ty>().ok();
        assert_eq!(parse_int::int_from_str::<$ty>($s).ok(), expected);
        assert_eq!(parse_int::int_from_string::<$ty>($s.to_owned()).ok(), expected);
        assert_eq!(parse_int::int_from_box::<$ty>($s.into()).ok(), expected);
    )*};
}

/// Checks the hex parsers against `from_str_radix` on digits.
macro_rules! check_hex {
    ($s:expr, $($ty:ty, $any:ident, $prefixed:ident, $unprefixed:ident);*) => {$(
        let prefixed = $s.strip_prefix("0x").or_else(|| $s.strip_prefix("0X"));
        let expected = <$ty>::from_str_radix(prefixed.unwrap_or($s), 16).ok();
        assert_eq!(parse_int::$any($s).ok(), expected);
        assert_eq!(parse_int::$prefixed($s).ok(), if prefixed.is_some() { expected } else { None });
        assert_eq!(parse_int::$unprefixed($s).ok(), if prefixed.is_none() { expected } else { None });
    )*};
}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let Ok(s) = u.arbitrary::<&str>() else { return };

    check_int!(s, i8, i16, i32, i64, i128, u8, u16, u32, u64, u128);
    check_hex!(
        s,
        u16, hex_u16, hex_u16_prefixed, hex_u16_unprefixed;
        u32, hex_u32, hex_u32_prefixed, hex_u32_unprefixed;
        u64, hex_u64, hex_u64_prefixed, hex_u64_unprefixed;
        u128, hex_u128, hex_u128_prefixed, hex_u128_unprefixed
    );
}

fuzz_target!(|data| {
    do_test(data);
});
