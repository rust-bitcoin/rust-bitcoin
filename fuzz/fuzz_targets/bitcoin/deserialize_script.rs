use bitcoin::address::Address;
use bitcoin::consensus::encode;
use bitcoin::script::{self, ScriptExt as _};
use bitcoin::Network;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let s: Result<script::ScriptBuf, _> = encode::deserialize(data);
    if let Ok(script) = s {
        let _: Result<Vec<script::Instruction>, script::Error> = script.instructions().collect();

        let mut b = script::Builder::new();
        for ins in script.instructions_minimal() {
            if ins.is_err() {
                return;
            }
            match ins.ok().unwrap() {
                script::Instruction::Op(op) => {
                    b = b.push_opcode(op);
                }
                script::Instruction::PushBytes(bytes) => {
                    // Any one-byte pushes, except -0, which can be interpreted as numbers, should be
                    // reserialized as numbers. (For -1 through 16, this will use special ops; for
                    // others it'll just reserialize them as pushes.)
                    if bytes.len() == 1 && bytes[0] != 0x80 && bytes[0] != 0x00 {
                        if let Ok(num) = bytes.read_scriptint() {
                            b = b.push_int(num);
                        } else {
                            b = b.push_slice(bytes);
                        }
                    } else {
                        b = b.push_slice(bytes);
                    }
                }
            }
        }
        assert_eq!(b.into_script(), script);
        assert_eq!(data, &encode::serialize(&script)[..]);

        // Check if valid address and if that address roundtrips.
        if let Ok(addr) = Address::from_script(&script, Network::Bitcoin) {
            assert_eq!(addr.script_pubkey(), script);
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
