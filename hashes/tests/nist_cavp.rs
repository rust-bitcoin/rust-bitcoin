// SPDX-License-Identifier: CC0-1.0

//! NIST CAVP test vectors.
//!
//! Test vectors from NIST SHA Validation System (SHAVS):
//! <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program>
//!

/// Tests both one-shot and incremental hashing
macro_rules! nist_shavs_tests {
    ($mod_name:ident, $hash_type:ty, $short_file:expr, $long_file:expr) => {
        mod $mod_name {
            use super::*;
            use bitcoin_hashes::HashEngine as _;

            fn hash_oneshot(data: &[u8]) -> Vec<u8> {
                <$hash_type>::hash(data).to_byte_array().to_vec()
            }

            // incremental hashing (byte by byte)
            fn hash_chunked(data: &[u8]) -> Vec<u8> {
                let mut engine = <$hash_type>::engine();
                for byte in data {
                    engine.input(&[*byte]);
                }
                bitcoin_hashes::HashEngine::finalize(engine).to_byte_array().to_vec()
            }

            #[test]
            fn short_msg() {
                let content = include_str!($short_file);
                run_shavs_tests(content, hash_oneshot);
                run_shavs_tests(content, hash_chunked);
            }

            #[test]
            fn long_msg() {
                let content = include_str!($long_file);
                run_shavs_tests(content, hash_oneshot);
                run_shavs_tests(content, hash_chunked);
            }
        }
    };
}

nist_shavs_tests!(sha1, bitcoin_hashes::sha1::Hash, "data/nist/SHA1ShortMsg.rsp", "data/nist/SHA1LongMsg.rsp");
nist_shavs_tests!(sha256, bitcoin_hashes::sha256::Hash, "data/nist/SHA256ShortMsg.rsp", "data/nist/SHA256LongMsg.rsp");
nist_shavs_tests!(sha384, bitcoin_hashes::sha384::Hash, "data/nist/SHA384ShortMsg.rsp", "data/nist/SHA384LongMsg.rsp");
nist_shavs_tests!(sha512, bitcoin_hashes::sha512::Hash, "data/nist/SHA512ShortMsg.rsp", "data/nist/SHA512LongMsg.rsp");
nist_shavs_tests!(sha512_256, bitcoin_hashes::sha512_256::Hash, "data/nist/SHA512_256ShortMsg.rsp", "data/nist/SHA512_256LongMsg.rsp");
nist_shavs_tests!(sha3_256, bitcoin_hashes::sha3_256::Hash, "data/nist/SHA3_256ShortMsg.rsp", "data/nist/SHA3_256LongMsg.rsp");

/// Runs NIST SHAVS tests from .rsp files
fn run_shavs_tests<F>(content: &str, hash_fn: F)
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let mut len_bits: Option<usize> = None;
    let mut msg: Option<Vec<u8>> = None;
    let mut count = 0;

    for line in content.lines() {
        let line = line.trim();

        // skip comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "Len" => len_bits = Some(value.parse().expect("invalid Len")),
                "Msg" => msg = Some(decode_hex(value)),
                "MD" => {
                    let expected = decode_hex(value);
                    let len = len_bits.expect("Len not set");
                    let m = msg.take().expect("Msg not set");

                    // when Len=0  message should be empty (NIST uses "00" as placeholder)
                    let input = if len == 0 { &[][..] } else { &m[..] };

                    let actual = hash_fn(input);
                    assert_eq!(actual, expected, "test {} failed (Len={})", count, len);
                    count += 1;
                    len_bits = None;
                }
                _ => {}
            }
        }
    }

    assert!(count > 0, "no test cases found");
}

fn decode_hex(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

