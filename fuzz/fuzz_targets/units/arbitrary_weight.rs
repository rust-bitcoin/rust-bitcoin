use arbitrary::{Arbitrary, Unstructured};
use bitcoin::Weight;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let w = Weight::arbitrary(&mut u);

    if let Ok(weight) = w {
        weight.to_wu();
        weight.to_kwu_ceil();
        weight.to_kwu_floor();
        weight.to_vbytes_ceil();
        weight.to_vbytes_floor();

        // Operations that take u64 as the rhs
        for operation in [Weight::checked_mul, Weight::checked_div] {
            if let Ok(val) = u.arbitrary() {
                let _ = operation(weight, val);
            } else {
                return;
            }
        }

        // Operations that take Weight as the rhs
        for operation in [Weight::checked_add, Weight::checked_sub] {
            if let Ok(val) = u.arbitrary() {
                let _ = operation(weight, val);
            } else {
                return;
            }
        }
    }

    // Constructors that return a Weight
    for constructor in [Weight::from_wu] {
        if let Ok(val) = u.arbitrary() {
            constructor(val);
        } else {
            return;
        }
    }

    // Constructors that return an Option<Weight>
    for constructor in [Weight::from_vb, Weight::from_kwu] {
        if let Ok(val) = u.arbitrary() {
            constructor(val);
        } else {
            return;
        }
    }
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
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
