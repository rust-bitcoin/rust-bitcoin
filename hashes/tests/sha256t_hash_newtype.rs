use bitcoin_hashes::{sha256t, sha256t_hash_newtype, HashEngine, Tag};

/// Same as the `sha256t` unit test, done here to make sure the macro works for external users.

const TEST_MIDSTATE: [u8; 32] = [
    156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147, 108,
    71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
];

sha256t_hash_newtype! {
    /// Tag to compute SHA-256 hash function pre-tagged with "example".
    struct NewTag = raw(TEST_MIDSTATE, 64);

    /// Output of the tagged SHA-256 hash function.
    struct TestHash(_);
}

// The digest created by sha256 hashing `&[0]` starting with `TEST_MIDSTATE`.
#[cfg(feature = "alloc")]
const HASH_ZERO: &str = "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829";

#[test]
#[cfg(feature = "alloc")]
fn hash_engine() {
    let mut engine = sha256t::Engine::<NewTag>::new();
    engine.input(&[0]);
    let digest = engine.finalize();
    let hash = sha256t::Hash::<NewTag>::from_byte_array(digest);

    let got = hash.to_string();
    assert_eq!(got, HASH_ZERO);
}

#[test]
#[cfg(feature = "alloc")]
fn hash_type() {
    let got = sha256t::Hash::<NewTag>::hash(&[0]).to_string();
    assert_eq!(got, HASH_ZERO);
}
