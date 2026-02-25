use arbitrary::{Arbitrary, Unstructured};
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);

    let Ok(bytes_a) = <&[u8]>::arbitrary(&mut unstructured) else {
        return;
    };
    let Ok(bytes_b) = <&[u8]>::arbitrary(&mut unstructured) else {
        return;
    };

    let Ok(psbt_a) = bitcoin::psbt::Psbt::deserialize(bytes_a) else {
        return;
    };

    let ser = bitcoin::psbt::Psbt::serialize(&psbt_a);
    let deser = bitcoin::psbt::Psbt::deserialize(&ser).unwrap();
    assert_eq!(ser, bitcoin::psbt::Psbt::serialize(&deser));

    let Ok(mut psbt_b) = bitcoin::psbt::Psbt::deserialize(bytes_b) else {
        return;
    };

    let mut psbt_a_clone = psbt_a.clone();
    assert_eq!(psbt_b.combine(psbt_a).is_ok(), psbt_a_clone.combine(psbt_b).is_ok());
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
