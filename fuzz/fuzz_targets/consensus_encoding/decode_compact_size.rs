#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

use bitcoin_consensus_encoding::{CompactSizeDecoder, Decoder};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut decoder = CompactSizeDecoder::new();
    let mut remaining = data;
    let push_result = decoder.push_bytes(&mut remaining);

    match push_result {
        Err(_) => {
            // Expected for invalid compact size encodings.
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
                    Ok(value) => {
                        // Verify the value is reasonable based on encoding size.
                        let consumed = data.len() - remaining.len();
                        assert!((1..=9).contains(&consumed));

                        match consumed {
                            1 => assert!(value < 0xFD),
                            3 => assert!((0xFD..=0xFFFF).contains(&value)),
                            5 => assert!((0x10000..=0xFFFFFFFF).contains(&value)),
                            9 => assert!((value as u64) >= 0x100000000), // Decoded values should only ever fit into a u64
                            _ => panic!("invalid compact size encoding length: {}", consumed),
                        }

                        if data.len() >= consumed {
                            assert_eq!(&data[consumed..], remaining);
                        }
                    }
                }
            }
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
