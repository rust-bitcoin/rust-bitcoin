#![no_main]

use libfuzzer_sys::fuzz_target;

fn do_test(data: &[u8]) {
    // We already fuzz Transactions in `./deserialize_transaction.rs`.
    let tx_result: Result<p2p::bip152::PrefilledTransaction, _> =
        bitcoin::consensus::encode::deserialize(data);

    match tx_result {
        Err(_) => {}
        Ok(tx) => {
            let ser = bitcoin::consensus::encode::serialize(&tx);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
