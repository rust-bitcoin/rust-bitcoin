// SPDX-License-Identifier: CC0-1.0

//! Parsing utilities.
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus the
//! `hex_*_unchecked` functions that 0.5.0 made private.

#[doc(inline)]
pub use units_v0_5::parse_int::*;

#[cfg(feature = "alloc")]
macro_rules! parse_prefixed_as_digits {
    ($any_hex_fn:ident, $s:expr) => {
        units_v0_5::parse_int::$any_hex_fn(&alloc::format!("0x{}", $s))
    };
}

#[cfg(not(feature = "alloc"))]
macro_rules! parse_prefixed_as_digits {
    ($any_hex_fn:ident, $s:expr) => {{
        let _ = $s;
        units_v0_5::parse_int::$any_hex_fn("0x0x")
    }};
}

macro_rules! hex_unchecked_for {
    ($int_type:ty; fn $any_hex_fn:ident(); fn $uncheck_hex_fn:ident();) => {
        #[doc = "Parses a `"]
        #[doc = stringify!($int_type)]
        #[doc = "` from an unprefixed hex string without first checking for a prefix.\n\n"]
        #[doc = "# Errors\n\n"]
        #[doc = "- If the input string contains a `0x` (or `0X`) prefix,"]
        #[doc = " returns `InvalidDigit` due to the `x`.\n"]
        #[doc = "- If the input string is not a valid hex encoding of a `"]
        #[doc = stringify!($int_type)]
        #[doc = "`."]
        #[inline]
        pub fn $uncheck_hex_fn(s: &str) -> Result<$int_type, ParseIntError> {
            if s.starts_with("0x") || s.starts_with("0X") {
                parse_prefixed_as_digits!($any_hex_fn, s)
            } else {
                units_v0_5::parse_int::$any_hex_fn(s)
            }
        }
    };
}

hex_unchecked_for!(
    u16;
    fn hex_u16();
    fn hex_u16_unchecked();
);
hex_unchecked_for!(
    u32;
    fn hex_u32();
    fn hex_u32_unchecked();
);
hex_unchecked_for!(
    u64;
    fn hex_u64();
    fn hex_u64_unchecked();
);
hex_unchecked_for!(
    u128;
    fn hex_u128();
    fn hex_u128_unchecked();
);

#[cfg(test)]
mod tests {
    use core::num::IntErrorKind;

    use super::*;

    fn assert_kind(error: ParseIntError, want: IntErrorKind) {
        assert_eq!(core::num::ParseIntError::from(error).kind(), &want);
    }

    #[test]
    fn parse_from_hex_unchecked_parses_unprefixed() {
        assert_eq!(hex_u16_unchecked("abcd"), Ok(0xabcd));
        assert_eq!(hex_u32_unchecked("1234abcd"), Ok(0x1234_abcd));
        assert_eq!(hex_u64_unchecked("deadbeefabcdffff"), Ok(0xdead_beef_abcd_ffff));
        assert_eq!(
            hex_u128_unchecked("deadbeefabcdffffdeadbeefabcdffff"),
            Ok(0xdead_beef_abcd_ffff_dead_beef_abcd_ffff)
        );
    }

    #[test]
    fn parse_from_hex_unchecked_errors_on_prefix() {
        assert_kind(hex_u16_unchecked("0xab").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u16_unchecked("0Xab").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u32_unchecked("0xab").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u32_unchecked("0Xab").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u64_unchecked("0xab").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u64_unchecked("0Xab").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u128_unchecked("0xdeadbeef").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u128_unchecked("0Xdeadbeef").unwrap_err(), IntErrorKind::InvalidDigit);
        assert_kind(hex_u32_unchecked("0x").unwrap_err(), IntErrorKind::InvalidDigit);
    }

    #[test]
    fn parse_from_hex_unchecked_errors_on_overflow() {
        assert_kind(hex_u16_unchecked("abcd1").unwrap_err(), IntErrorKind::PosOverflow);
        assert_kind(hex_u32_unchecked("1234abcd1").unwrap_err(), IntErrorKind::PosOverflow);
        assert_kind(hex_u64_unchecked("deadbeefabcdffff1").unwrap_err(), IntErrorKind::PosOverflow);
        assert_kind(
            hex_u128_unchecked("deadbeefabcdffffdeadbeefabcdffff1").unwrap_err(),
            IntErrorKind::PosOverflow,
        );
    }

    #[test]
    fn parse_from_hex_unchecked_errors_on_empty_and_invalid() {
        assert_kind(hex_u32_unchecked("").unwrap_err(), IntErrorKind::Empty);
        assert_kind(hex_u32_unchecked("xyz").unwrap_err(), IntErrorKind::InvalidDigit);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn parse_from_hex_unchecked_error_reports_whole_input() {
        use alloc::string::ToString;

        let prefixed = hex_u32_unchecked("0xab").unwrap_err().to_string();
        assert!(prefixed.contains("'0xab'"), "{}", prefixed);
        assert!(prefixed.contains("unsigned, 32-bit"), "{}", prefixed);

        let overflow = hex_u16_unchecked("abcd1").unwrap_err().to_string();
        assert!(overflow.contains("'abcd1'"), "{}", overflow);
        assert!(overflow.contains("unsigned, 16-bit"), "{}", overflow);
    }
}
