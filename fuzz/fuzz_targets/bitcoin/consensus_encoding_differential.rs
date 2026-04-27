use honggfuzz::fuzz;

#[cfg(rust_v_1_65)]
macro_rules! assert_new_encoding_matches_legacy {
    ($data:expr, $local_ty:path) => {{
        let legacy = bitcoin::consensus::encode::deserialize_partial::<$local_ty>($data);
        let mut remaining = $data;
        let new = bitcoin::encoding::decode_from_slice_unbounded::<$local_ty>(&mut remaining);
        let new_consumed = $data.len() - remaining.len();

        match (legacy, new) {
            (Ok((legacy_value, legacy_consumed)), Ok(new_value)) => {
                assert_eq!(new_consumed, legacy_consumed);
                assert_eq!(
                    bitcoin::consensus::encode::serialize(&legacy_value),
                    &$data[..legacy_consumed]
                );
                assert_eq!(
                    bitcoin::consensus::encode::serialize(&legacy_value),
                    bitcoin::encoding::encode_to_vec(&new_value)
                );
            }
            (Err(_), Err(_)) => {}
            (legacy, new) => {
                panic!(
                    "legacy/new encoding mismatch for {}: legacy={:?} new={:?}",
                    stringify!($local_ty),
                    legacy,
                    new
                )
            }
        }
    }};
}

#[cfg(not(rust_v_1_65))]
macro_rules! assert_new_encoding_matches_legacy {
    ($data:expr, $local_ty:path) => {{
        let _ = ($data, stringify!($local_ty));
    }};
}

fn do_test(data: &[u8]) {
    macro_rules! check_type {
        ($local_ty:path) => {{
            assert_new_encoding_matches_legacy!(data, $local_ty);
        }};
    }

    check_type!(bitcoin::Transaction);
    check_type!(bitcoin::Block);
    check_type!(bitcoin::p2p::message::RawNetworkMessage);
    check_type!(bitcoin::p2p::address::Address);
    check_type!(bitcoin::merkle_tree::MerkleBlock);
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
    #[test]
    fn duplicate_crash() { super::do_test(&[0x00]); }
}
