use bitcoin::hashes::{ripemd160, sha1, sha256d, sha512, Hmac};
use honggfuzz::fuzz;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Hmacs {
    sha1: Hmac<sha1::Hash>,
    sha512: Hmac<sha512::Hash>,
}

#[derive(Deserialize, Serialize)]
struct Main {
    hmacs: Hmacs,
    ripemd: ripemd160::Hash,
    sha2d: sha256d::Hash,
}

fn do_test(data: &[u8]) {
    if let Ok(m) = serde_json::from_slice::<Main>(data) {
        let vec = serde_json::to_vec(&m).unwrap();
        assert_eq!(data, &vec[..]);
    }
}

fn main() {
    loop {
        fuzz!(|d| { do_test(d) });
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
        extend_vec_from_hex("00000", &mut a);
        super::do_test(&a);
    }
}
