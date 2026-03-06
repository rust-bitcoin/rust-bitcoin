// SPDX-License-Identifier: CC0-1.0

//! For a hash with block size `B`, this checks all `(i, j, k)` in `0..=B` and
//! verifies that feeding the same bytes via three `engine.input()` calls
//! matches one-shot hashing.
//!
//! This catches bugs that byte-by-byte incremetal tests in `nist_cavp.rs` don't catch.
//! especially block-boundary transitions, empty chunks or buffering bugs.
//!
//! Inspired by `ring` `test_i_u_f` tests:
//! <https://github.com/briansmith/ring/commit/5daff2c0e1bb8ef00e44e15b0531dda0b69d0ec5>
//!
//! These tests are slow, so they only run in release mode

#[cfg(not(debug_assertions))]
use bitcoin_hashes::HashEngine as _;

macro_rules! chunk_combination_test {
    ($test_name:ident, $hash_type:ty, $block_size:expr) => {
        #[cfg(not(debug_assertions))]
        #[test]
        fn $test_name() {
            let max = $block_size + 1;
            let input: Vec<u8> = (0..max * 3).map(|i| (i & 0xff) as u8).collect();

            for i in 0..max {
                for j in 0..max {
                    for k in 0..max {
                        let total = i + j + k;
                        let part1 = &input[..i];
                        let part2 = &input[i..i + j];
                        let part3 = &input[i + j..total];

                        let mut engine = <$hash_type>::engine();
                        engine.input(part1);
                        engine.input(part2);
                        engine.input(part3);
                        let chunked = bitcoin_hashes::HashEngine::finalize(engine);

                        let oneshot = <$hash_type>::hash(&input[..total]);

                        assert_eq!(chunked.to_byte_array(), oneshot.to_byte_array());
                    }
                }
            }
        }
    };
}

chunk_combination_test!(sha1, bitcoin_hashes::sha1::Hash, 64);
chunk_combination_test!(sha256, bitcoin_hashes::sha256::Hash, 64);
chunk_combination_test!(sha3_256, bitcoin_hashes::sha3_256::Hash, 136);
chunk_combination_test!(sha384, bitcoin_hashes::sha384::Hash, 128);
chunk_combination_test!(sha512, bitcoin_hashes::sha512::Hash, 128);
chunk_combination_test!(sha512_256, bitcoin_hashes::sha512_256::Hash, 128);
chunk_combination_test!(ripemd160, bitcoin_hashes::ripemd160::Hash, 64);
