//! Tests for `Transaction`. Data lives in `tests/data`, which is excluded when publishing.

use bitcoin::Transaction;

#[test]
fn huge_witness() {
    let hex = hex::decode_to_vec(include_str!("data/huge_witness.hex").trim()).unwrap();
    encoding::decode_from_slice::<Transaction>(&hex).unwrap();
}
