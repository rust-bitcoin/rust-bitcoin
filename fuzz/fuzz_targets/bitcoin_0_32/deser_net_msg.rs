#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let _: Result<bitcoin_0_32::p2p::message::RawNetworkMessage, _> =
        bitcoin_0_32::consensus::encode::deserialize(data);
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
