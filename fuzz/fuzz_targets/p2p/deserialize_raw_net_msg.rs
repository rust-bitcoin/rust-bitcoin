#![no_main]

use libfuzzer_sys::fuzz_target;

fn do_test(data: &[u8]) {
    let _: Result<p2p::message::RawNetworkMessage, _> =
        bitcoin::consensus::encode::deserialize(data);
}

fuzz_target!(|data| {
    do_test(data);
});
