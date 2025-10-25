use bitcoin_consensus_encoding::{ArrayDecoder, Decoder, Decoder2};
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let mut decoder = Decoder2::new(ArrayDecoder::<2>::new(), ArrayDecoder::<3>::new());
    let mut remaining = data;

    let push_result = decoder.push_bytes(&mut remaining);

    match push_result {
        Err(_) => {
            // Expected for invalid data
        }
        Ok(needs_more) => {
            if needs_more {
                let end_result = decoder.end();
                assert!(
                    end_result.is_err(),
                    "decoder should error when insufficient data provided"
                );
            } else {
                let end_result = decoder.end();
                match end_result {
                    Err(_) => {
                        // Unexpected for array decoders with sufficient data.
                    }
                    Ok((first_array, second_array)) => {
                        assert_eq!(first_array.len(), 2);
                        assert_eq!(second_array.len(), 3);
                        if data.len() >= 5 {
                            assert_eq!(&data[5..], remaining);
                            assert_eq!(&first_array[..], &data[..2]);
                            assert_eq!(&second_array[..], &data[2..5]);
                        }
                    }
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
        extend_vec_from_hex("0102030405", &mut a);
        super::do_test(&a);
    }
}
