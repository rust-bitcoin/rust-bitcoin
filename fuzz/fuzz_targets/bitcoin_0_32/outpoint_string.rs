#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let lowercase: Vec<u8> = data
        .iter()
        .map(|c| match *c {
            b'A' => b'a',
            b'B' => b'b',
            b'C' => b'c',
            b'D' => b'd',
            b'E' => b'e',
            b'F' => b'f',
            x => x,
        })
        .collect();
    let data_str = match String::from_utf8(lowercase) {
        Err(_) => return,
        Ok(s) => s,
    };
    match data_str.parse::<bitcoin_0_32::blockdata::transaction::OutPoint>() {
        Ok(op) => {
            assert_eq!(op.to_string().as_bytes(), data_str.as_bytes());
        }
        Err(_) => {
            // If we can't deserialize as a string, try consensus deserializing
            let res: Result<bitcoin_0_32::blockdata::transaction::OutPoint, _> =
                bitcoin_0_32::consensus::encode::deserialize(data);
            if let Ok(deser) = res {
                let ser = bitcoin_0_32::consensus::encode::serialize(&deser);
                assert_eq!(ser, data);
                let string = deser.to_string();
                match string.parse::<bitcoin_0_32::blockdata::transaction::OutPoint>() {
                    Ok(destring) => assert_eq!(destring, deser),
                    Err(_) => panic!(),
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
