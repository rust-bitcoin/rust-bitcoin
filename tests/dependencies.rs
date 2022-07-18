//! This file does arbitrary comparisons of various types to ensure all the dependency versions
//! are equal. It exists to catch our mistakes when upgrading crates in the stack.

#[test]
fn bitcoin_hashes() {
    let our_dep = bitcoin_hashes::hex::Error::InvalidChar(0_u8);
    let secp_dep = secp256k1::hashes::hex::Error::InvalidChar(0_u8);
    assert_eq!(our_dep, secp_dep)
}
