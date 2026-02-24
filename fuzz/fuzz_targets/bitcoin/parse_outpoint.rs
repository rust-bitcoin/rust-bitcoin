#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

use bitcoin::consensus::encode;
use bitcoin::transaction::OutPoint;

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
    match data_str.parse::<OutPoint>() {
        Ok(op) => {
            assert_eq!(op.to_string().as_bytes(), data_str.as_bytes());
        }
        Err(_) => {
            // If we can't deserialize as a string, try consensus deserializing
            let res: Result<OutPoint, _> = encode::deserialize(data);
            if let Ok(deser) = res {
                let ser = encode::serialize(&deser);
                assert_eq!(ser, data);
                let string = deser.to_string();
                match string.parse::<OutPoint>() {
                    Ok(destring) => assert_eq!(destring, deser),
                    Err(_) => panic!(),
                }
            }
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
