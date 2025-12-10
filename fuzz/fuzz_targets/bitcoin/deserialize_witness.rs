#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoin::witness::Witness;

fn do_test(data: &[u8]) {
    let witness_result: Result<Witness, _> = bitcoin::consensus::encode::deserialize(data);

    match witness_result {
        Err(_) => {}
        Ok(witness) => {
            let ser = bitcoin::consensus::encode::serialize(&witness);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
