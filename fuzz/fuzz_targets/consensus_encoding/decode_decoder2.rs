#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

use bitcoin_consensus_encoding::{ArrayDecoder, Decoder, Decoder2};

#[cfg(not(fuzzing))]
fn main() {}

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

fuzz_target!(|data| {
    do_test(data);
});

