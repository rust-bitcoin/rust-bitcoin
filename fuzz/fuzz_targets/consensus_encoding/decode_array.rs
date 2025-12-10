#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoin_consensus_encoding::{ArrayDecoder, Decoder};

fn do_test(data: &[u8]) {
    test_array_decoder::<1>(data);
    test_array_decoder::<2>(data);
    test_array_decoder::<4>(data);
    test_array_decoder::<8>(data);
    test_array_decoder::<16>(data);
    test_array_decoder::<32>(data);
}

fn test_array_decoder<const N: usize>(data: &[u8]) {
    let mut decoder = ArrayDecoder::<N>::new();
    let mut remaining = data;
    let push_result = decoder.push_bytes(&mut remaining);

    match push_result {
        Err(_) => {
            // Expected for invalid data or other parsing errors.
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
                        // Unexpected, but could happen due to internal state issues.
                    }
                    Ok(array) => {
                        // Verify the array has the expected size.
                        assert_eq!(array.len(), N);
                        // Verify the array contains the expected data from input.
                        if data.len() >= N {
                            assert_eq!(&array[..], &data[..N]);
                            assert_eq!(&data[N..], remaining);
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
