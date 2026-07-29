#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    // We already fuzz Transactions in `./deserialize_transaction.rs`.
    let tx_result: Result<p2p::bip152::PrefilledTransaction, _> =
        bitcoin_consensus_encoding::decode_from_slice(data);

    match tx_result {
        Err(_) => {}
        Ok(tx) => {
            let ser = bitcoin_consensus_encoding::encode_to_vec(&tx);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
