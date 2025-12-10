#![no_main]

use libfuzzer_sys::fuzz_target;

fn do_test(data: &[u8]) {
    let _: Result<p2p::address::AddrV2, _> = bitcoin::consensus::encode::deserialize(data);
}

fuzz_target!(|data| {
    do_test(data);
});
