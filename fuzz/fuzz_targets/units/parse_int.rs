#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use arbitrary::Unstructured;

use bitcoin::parse_int;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);

    if let Ok(s) = u.arbitrary::<&str>() {
        let _ = parse_int::int_from_str::<i8>(s);
        let _ = parse_int::int_from_str::<i16>(s);
        let _ = parse_int::int_from_str::<i32>(s);
        let _ = parse_int::int_from_str::<i64>(s);
        let _ = parse_int::int_from_str::<i128>(s);

        let _ = parse_int::int_from_str::<u8>(s);
        let _ = parse_int::int_from_str::<u16>(s);
        let _ = parse_int::int_from_str::<u32>(s);
        let _ = parse_int::int_from_str::<u64>(s);
        let _ = parse_int::int_from_str::<u128>(s);

        let _ = parse_int::hex_remove_prefix(s);

        if parse_int::hex_u32_prefixed(s).is_ok() {
            assert!(parse_int::hex_u32(s).is_ok());
            assert!(parse_int::hex_u32_unprefixed(s).is_err());
        }

        if parse_int::hex_u32_unprefixed(s).is_ok() {
            assert!(parse_int::hex_u32(s).is_ok());
            assert!(parse_int::hex_u32_prefixed(s).is_err());
        }

        if parse_int::hex_u128_prefixed(s).is_ok() {
            assert!(parse_int::hex_u128(s).is_ok());
            assert!(parse_int::hex_u128_unprefixed(s).is_err());
        }

        if parse_int::hex_u128_unprefixed(s).is_ok() {
            assert!(parse_int::hex_u128(s).is_ok());
            assert!(parse_int::hex_u128_prefixed(s).is_err());
        }
    }

    if let Ok(s) = u.arbitrary::<String>() {
        let _ = parse_int::int_from_string::<i8>(s.clone());
        let _ = parse_int::int_from_string::<i16>(s.clone());
        let _ = parse_int::int_from_string::<i32>(s.clone());
        let _ = parse_int::int_from_string::<i64>(s.clone());
        let _ = parse_int::int_from_string::<i128>(s.clone());

        let _ = parse_int::int_from_string::<u8>(s.clone());
        let _ = parse_int::int_from_string::<u16>(s.clone());
        let _ = parse_int::int_from_string::<u32>(s.clone());
        let _ = parse_int::int_from_string::<u64>(s.clone());
        let _ = parse_int::int_from_string::<u128>(s);
    }

    if let Ok(s) = u.arbitrary::<Box<str>>() {
        let _ = parse_int::int_from_box::<i8>(s.clone());
        let _ = parse_int::int_from_box::<i16>(s.clone());
        let _ = parse_int::int_from_box::<i32>(s.clone());
        let _ = parse_int::int_from_box::<i64>(s.clone());
        let _ = parse_int::int_from_box::<i128>(s.clone());

        let _ = parse_int::int_from_box::<u8>(s.clone());
        let _ = parse_int::int_from_box::<u16>(s.clone());
        let _ = parse_int::int_from_box::<u32>(s.clone());
        let _ = parse_int::int_from_box::<u64>(s.clone());
        let _ = parse_int::int_from_box::<u128>(s);
    }
}

fuzz_target!(|data| {
    do_test(data);
});
