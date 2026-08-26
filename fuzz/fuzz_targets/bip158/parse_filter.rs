#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::BlockHash;
use bitcoin_bip158::BasicFilter;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let Ok(filter) = BasicFilter::from_bytes(data) else { return };
    assert_eq!(filter.as_bytes(), data);

    let mut hash_bytes = [0u8; 32];
    let hash_len = data.len().min(hash_bytes.len());
    hash_bytes[..hash_len].copy_from_slice(&data[..hash_len]);
    let block_hash = BlockHash::from_byte_array(hash_bytes);
    let queries = data.chunks(8).take(8).collect::<Vec<_>>();

    assert_eq!(
        filter.match_any(block_hash, &queries),
        queries.iter().any(|query| filter.match_any(block_hash, [query]))
    );
    assert_eq!(
        filter.match_all(block_hash, &queries),
        queries.iter().all(|query| filter.match_all(block_hash, [query]))
    );
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
