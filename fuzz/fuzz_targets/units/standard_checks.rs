use bitcoin::absolute::{Height, MedianTimePast};
use bitcoin::relative::{NumberOf512Seconds, NumberOfBlocks};
use bitcoin::{
    Amount, BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate,
    Sequence, SignedAmount, Weight,
};
use honggfuzz::fuzz;
use standard_test::StandardChecks as _;

/// Implements the traits on the wrapper type $ty. Intended only to be called from inside wrap_for_checks!
macro_rules! _impl_traits_on_wrapper {
    ($ty:ident$(, $default:expr)?) => {
        impl<'a> arbitrary::Arbitrary<'a> for $ty {
            fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
                Ok(Self(super::$ty::arbitrary(u)?))
            }
        }

        impl core::ops::Deref for $ty {
            type Target = super::$ty;

            fn deref(&self) -> &Self::Target { &self.0 }
        }

        $(
            impl Default for $ty {
                fn default() -> $ty { Self($default) }
            }
        )?

        standard_checks!($ty);
    };
}

/// Create a wrapper type for a foreign type so that we can use standard_checks! on it from here.
macro_rules! wrap_for_checks {
    ($ty:ident) => {
        #[derive(Default)]
        pub(crate) struct $ty(super::$ty);

        _impl_traits_on_wrapper!($ty);
    };
    ($ty:ident, $default:expr) => {
        pub(crate) struct $ty(super::$ty);

        _impl_traits_on_wrapper!($ty, $default);
    };
}

mod fuzz {
    use standard_test::standard_checks;

    wrap_for_checks!(Amount);
    wrap_for_checks!(BlockHeightInterval);
    wrap_for_checks!(BlockMtpInterval);
    wrap_for_checks!(NumberOf512Seconds);
    wrap_for_checks!(NumberOfBlocks);
    wrap_for_checks!(Sequence);
    wrap_for_checks!(SignedAmount);

    // Structs that need defaults
    wrap_for_checks!(BlockHeight, super::BlockHeight::MIN);
    wrap_for_checks!(BlockMtp, super::BlockMtp::from_u32(1_742_979_600)); // 26 Mar 2025 9:00 UTC
    wrap_for_checks!(BlockTime, super::BlockTime::from(1_742_979_600)); // 26 Mar 2025 9:00 UTC
    wrap_for_checks!(FeeRate, super::FeeRate::BROADCAST_MIN);
    wrap_for_checks!(Height, super::Height::MIN);
    wrap_for_checks!(MedianTimePast, super::MedianTimePast::MIN);
    wrap_for_checks!(Weight, super::Weight::MIN_TRANSACTION);
}

fn do_test(data: &[u8]) {
    fuzz::Amount::one_iteration(data);
    fuzz::BlockHeight::one_iteration(data);
    fuzz::BlockHeightInterval::one_iteration(data);
    fuzz::BlockMtp::one_iteration(data);
    fuzz::BlockMtpInterval::one_iteration(data);
    fuzz::BlockTime::one_iteration(data);
    fuzz::FeeRate::one_iteration(data);
    fuzz::Height::one_iteration(data);
    fuzz::NumberOf512Seconds::one_iteration(data);
    fuzz::NumberOfBlocks::one_iteration(data);
    fuzz::MedianTimePast::one_iteration(data);
    fuzz::Sequence::one_iteration(data);
    fuzz::SignedAmount::one_iteration(data);
    fuzz::Weight::one_iteration(data);
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00000000", &mut a);
        super::do_test(&a);
    }
}
