use bitcoin_fuzz::fuzz_utils::consume_random_bytes;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let mut new_data = data;
    let bytes = consume_random_bytes(&mut new_data);
    let psbt: Result<bitcoin::psbt::Psbt, _> = bitcoin::psbt::Psbt::deserialize(bytes);
    match psbt {
        Err(_) => {}
        Ok(mut psbt) => {
            let ser = bitcoin::psbt::Psbt::serialize(&psbt);
            let deser = bitcoin::psbt::Psbt::deserialize(&ser).unwrap();
            // Since the fuzz data could order psbt fields differently, we compare to our deser/ser instead of data
            assert_eq!(ser, bitcoin::psbt::Psbt::serialize(&deser));

            let new_bytes = consume_random_bytes(&mut new_data);
            let psbt_b: Result<bitcoin::psbt::Psbt, _> =
                bitcoin::psbt::Psbt::deserialize(new_bytes);
            match psbt_b {
                Err(_) => {}
                Ok(mut psbt_b) => {
                    assert_eq!(psbt_b.combine(psbt.clone()).is_ok(), psbt.combine(psbt_b).is_ok());
                }
            }
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
