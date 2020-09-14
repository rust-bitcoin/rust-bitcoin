extern crate bitcoin;
use std::str::FromStr;
use std::convert::Into;

fn do_test(data: &[u8]) {
    macro_rules! read_ints {
        ($start: expr) => { {
            let mut native = 0;
            for c in data[$start..$start + 16].iter() {
                native <<= 8;
                native |= (*c) as u128;
            }
            // Note BE:
            let uint128 = bitcoin::util::uint::Uint128::from(&[native as u64, (native >> 8*8) as u64][..]);

            // Checking two conversion methods against each other
            let mut slice = [0u8; 16];
            slice.copy_from_slice(&data[$start..$start + 16]);
            assert_eq!(uint128, bitcoin::util::uint::Uint128::from_be_bytes(slice));

            (native, uint128)
        } }
    }
    macro_rules! check_eq {
        ($native: expr, $uint: expr) => { {
            assert_eq!(&[$native as u64, ($native >> 8*8) as u64], $uint.as_bytes());
        } }
    }

    if data.len() != 16*2 + 1 { return; }
    let (a_native, a) = read_ints!(0);

    // Checks using only a:
    for i in 0..128 {
        check_eq!(a_native << i, a << i);
        check_eq!(a_native >> i, a >> i);
    }
    assert_eq!(a_native as u64, a.low_u64());
    assert_eq!(a_native as u32, a.low_u32());
    assert_eq!(128 - a_native.leading_zeros() as usize, a.bits());
    assert_eq!(a_native as u64, bitcoin::util::uint::Uint128::from_u64(a_native as u64).unwrap().low_u64());

    // Checks with two numbers:
    let (b_native, b) = read_ints!(16);

    check_eq!(a_native.wrapping_add(b_native), a + b);
    check_eq!(a_native.wrapping_sub(b_native), a - b);
    if b_native != 0 {
        check_eq!(a_native.wrapping_div(b_native), a / b);
        check_eq!(a_native.wrapping_rem(b_native), a % b);
    }
    check_eq!(a_native.wrapping_mul(b_native), a * b);
    check_eq!(a_native & b_native, a & b);
    check_eq!(a_native | b_native, a | b);
    check_eq!(a_native ^ b_native, a ^ b);
    check_eq!(a_native.wrapping_mul((b_native as u32) as u128), a.mul_u32(b.low_u32()));

    assert_eq!(a_native > b_native, a > b);
    assert_eq!(a_native >= b_native, a >= b);
    assert_eq!(a_native < b_native, a < b);
    assert_eq!(a_native <= b_native, a <= b);
}

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
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
        extend_vec_from_hex("100000a70000000000000000000000000000000000000000000000000000000054", &mut a);
        super::do_test(&a);
    }
}
