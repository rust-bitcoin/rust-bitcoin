use std::str::FromStr;

use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::consensus;
use honggfuzz::fuzz;

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
    match OutPoint::from_str(&data_str) {
        Ok(op) => {
            assert_eq!(op.to_string().as_bytes(), data_str.as_bytes());
        }
        Err(_) => {
            // If we can't deserialize as a string, try consensus deserializing
            let res: Result<OutPoint, _> = consensus::deserialize(data);
            if let Ok(deser) = res {
                let ser = consensus::serialize(&deser);
                assert_eq!(ser, data);
                let string = deser.to_string();
                match OutPoint::from_str(&string) {
                    Ok(destring) => assert_eq!(destring, deser),
                    Err(_) => panic!(),
                }
            }
        }
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
