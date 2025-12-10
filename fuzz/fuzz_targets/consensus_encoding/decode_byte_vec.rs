#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoin_consensus_encoding::{ByteVecDecoder, Decoder};

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

fuzz_target!(|data| {
    do_test(data);
});
