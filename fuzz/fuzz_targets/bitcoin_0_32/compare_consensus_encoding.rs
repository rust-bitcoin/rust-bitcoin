#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use old_bitcoin::absolute;
use old_bitcoin::consensus::encode::deserialize_partial;
use old_bitcoin::consensus::serialize;
use old_bitcoin::encoding::{self, decode_from_slice_unbounded};

#[cfg(not(fuzzing))]
fn main() {}

macro_rules! compare_encoding {
    ($data:expr, $ty:ident) => {
        compare_encoding!($data, old_bitcoin::$ty);
    };

    ($data:expr, $ty:ty) => {{
        // Use partial/unbounded decoding so the fuzzer can exercise the actual parsing
        // logic even when the input is longer than the encoded type. Using strict
        // deserialize() would reject any input with trailing bytes, reducing coverage.
        let old_result = deserialize_partial::<$ty>($data);
        let mut rem = &*$data;
        let new_result: Result<$ty, _> = decode_from_slice_unbounded(&mut rem);

        match (old_result, new_result) {
            (Ok((old_obj, old_consumed)), Ok(new_obj)) => {
                assert_eq!(old_obj, new_obj);
                let new_consumed = $data.len() - rem.len();
                assert_eq!(
                    old_consumed, new_consumed,
                    "decoders consumed different number of bytes: legacy={old_consumed}, new={new_consumed}"
                );
                let old_encoded = serialize(&old_obj);
                let new_encoded = encoding::encode_to_vec(&new_obj);
                assert_eq!(old_encoded, new_encoded);
            }
            (Err(_), Err(_)) => {}
            (Ok((old_obj, _)), Err(err)) => {
                panic!("legacy decoder accepted {old_obj:?}, new decoder failed: {err:?}");
            }
            (Err(err), Ok(new_obj)) => {
                panic!("new decoder accepted {new_obj:?}, legacy decoder failed: {err:?}");
            }
        }
    }};
}

fn do_test(data: &[u8]) {
    // Split data evenly so the fuzzer can independently explore each type's input space.
    // Each type gets its own non-overlapping sub-slice; `Amount` needs 8 bytes (u64 LE),
    // the rest need 4 bytes (u32 LE). Trailing bytes in each slice are tolerated by the
    // partial/unbounded decoders used in `compare_encoding!`.
    let n = data.len() / 4;
    compare_encoding!(&data[..n], Amount);
    compare_encoding!(&data[n..2 * n], Sequence);
    compare_encoding!(&data[2 * n..3 * n], CompactTarget);
    compare_encoding!(&data[3 * n..4 * n], absolute::LockTime);
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
