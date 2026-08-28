#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin_fuzz::mutate::p2p_frame;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let _: Result<p2p::message::V1NetworkMessage, _> =
        bitcoin_consensus_encoding::decode_from_slice(data);
}

fuzz_target!(|data| {
    do_test(data);
});

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    p2p_frame::mutate_payload(data, size, max_size, seed, libfuzzer_sys::fuzzer_mutate)
});
