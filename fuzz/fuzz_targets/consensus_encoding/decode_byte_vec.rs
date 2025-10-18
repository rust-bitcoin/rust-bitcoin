use bitcoin_consensus_encoding::{ByteVecDecoder, Decoder};
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let mut decoder = ByteVecDecoder::new();
    let mut remaining = data;
    let push_result = decoder.push_bytes(&mut remaining);

    match push_result {
        Err(_) => {
            // Expected for invalid data or allocation limits.
        }
        Ok(needs_more) => {
            if needs_more {
                // Decoder needs more data, but we've given it all we have
                // This should result in an error when we call end().
                let end_result = decoder.end();
                assert!(
                    end_result.is_err(),
                    "decoder should error when insufficient data provided"
                );
            } else {
                let end_result = decoder.end();
                match end_result {
                    Err(_) => {
                        // Could happen for invalid compact size formats.
                    }
                    Ok(vec) => {
                        // Validate that result makes sense, can't produce more data than input and 32MB limit.
                        assert!(vec.len() <= data.len());
                        if !vec.is_empty() {
                            assert!(vec.len() <= 0x02000000);
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
        extend_vec_from_hex("03010203", &mut a);
        super::do_test(&a);
    }
}
