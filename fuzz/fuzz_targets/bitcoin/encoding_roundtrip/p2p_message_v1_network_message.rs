#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin_fuzz::check_roundtrip;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fuzz_target!(|data: &[u8]| {
    check_roundtrip::<p2p::message::V1NetworkMessage>(data);
});

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    bitcoin_fuzz::mutate::p2p_frame::mutate_payload(
        data,
        size,
        max_size,
        seed,
        libfuzzer_sys::fuzzer_mutate,
    )
});
