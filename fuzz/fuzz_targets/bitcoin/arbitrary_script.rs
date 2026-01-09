#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use bitcoin::address::Address;
use bitcoin::consensus::serialize;
use bitcoin::script::{self, ScriptBuf, ScriptExt as _, ScriptPubKeyExt as _};
use bitcoin::Network;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let s = ScriptBuf::arbitrary(&mut u);

    if let Ok(script_buf) = s {
        let serialized = serialize(&script_buf);
        let _: Result<Vec<script::Instruction>, script::Error> =
            script_buf.instructions().collect();

        let _ = script_buf.to_string();
        let _ = script_buf.count_sigops();
        let _ = script_buf.count_sigops_legacy();
        let _ = script_buf.minimal_non_dust();
        let _ = script_buf.minimal_non_dust_custom(u.arbitrary().expect("valid arbitrary FeeRate"));

        let mut builder = script::Builder::new();
        for instruction in script_buf.instructions_minimal() {
            if instruction.is_err() {
                return;
            }
            match instruction.ok().unwrap() {
                script::Instruction::Op(op) => {
                    builder = builder.push_opcode(op);
                }
                script::Instruction::PushBytes(bytes) => {
                    // While we enforce the minimality rule for minimal PUSHDATA opcodes, we don't
                    // enforce the minimality of numbers since we don't have a script engine
                    // to determine if the number is getting fed into a numeric opcode, which is
                    // when the minimality of numbers is required.
                    builder = builder.push_slice_non_minimal(bytes)
                }
            }
        }
        assert_eq!(builder.into_script(), script_buf);
        assert_eq!(serialized, &serialize(&script_buf)[..]);

        // Check if valid address and if that address roundtrips.
        if let Ok(addr) = Address::from_script(&script_buf, Network::Bitcoin) {
            assert_eq!(addr.script_pubkey(), script_buf);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
