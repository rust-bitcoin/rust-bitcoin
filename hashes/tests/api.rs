// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `units`.
//!
//! The point of these tests is to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

// Import using module style e.g., `sha256::Hash`.
use bitcoin_hashes::{
    hash160, hash_newtype, hkdf, hmac, ripemd160, sha1, sha256, sha256d, sha256t, sha256t_tag,
    sha384, sha3_256, sha512, sha512_256, siphash24, Hash, HashEngine,
};
// Import using type alias style e.g., `Sha256`.
use bitcoin_hashes::{
    Hash160, Hkdf, Hmac, HmacEngine, Ripemd160, Sha1, Sha256, Sha256d, Sha256t, Sha384, Sha3_256,
    Sha512, Sha512_256, Siphash24,
};

// Arbitrary midstate value; taken from as sha256t unit tests.
const TEST_MIDSTATE: [u8; 32] = [
    156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147, 108,
    71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
];

sha256t_tag! {
    /// Test tag so we don't have to use generics.
    #[derive(Debug)]
    struct Tag = raw(TEST_MIDSTATE, 64);
}
hash_newtype! {
    /// A concrete sha256t hash type so we don't have to use generics.
    #[derive(Debug)]
    struct TaggedHash(sha256t::Hash<Tag>);
}

/// All the hash types excluding `Hkdf`.
// `Hkdf` only implements `Copy` and `Clone` ATM - by design.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)] // C-COMMON-TRAITS
// We check `Hkdf` implements `Debug` in the non-empty debug test below.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Hashes<T: Hash> {
    a: hash160::Hash,
    c: Hmac<T>,
    d: ripemd160::Hash,
    e: sha1::Hash,
    f: sha256::Hash,
    g: sha256d::Hash,
    h: TaggedHash,
    i: sha384::Hash,
    j: sha512::Hash,
    k: sha512_256::Hash,
    l: siphash24::Hash,
    m: sha3_256::Hash,
}

impl Hashes<Sha256> {
    fn new_sha256() -> Self {
        let hmac = HmacEngine::<sha256::HashEngine>::new(&[]).finalize();
        // `TaggedHash` is not a general hash but `Sha256<Tag>` is.
        let tagged = TaggedHash::from_byte_array(Sha256t::<Tag>::hash(&[]).to_byte_array());
        let siphash = Siphash24::from_engine(siphash24::HashEngine::with_keys(0, 0));

        Self {
            a: Hash160::hash(&[]),
            // b: hkdf,
            c: hmac,
            d: Ripemd160::hash(&[]),
            e: Sha1::hash(&[]),
            f: Sha256::hash(&[]),
            g: Sha256d::hash(&[]),
            h: tagged,
            i: Sha384::hash(&[]),
            j: Sha512::hash(&[]),
            k: Sha512_256::hash(&[]),
            l: siphash,
            m: Sha3_256::hash(&[]),
        }
    }
}

/// All the hash engines.
#[derive(Clone)] // C-COMMON-TRAITS
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Engines {
    a: hash160::HashEngine,
    // We cannot derive `Debug` on a generic `HmacEngine<T>` engine.
    b: hmac::HmacEngine<sha256::HashEngine>,
    c: ripemd160::HashEngine,
    d: sha1::HashEngine,
    e: sha256::HashEngine,
    f: sha256d::HashEngine,
    g: sha256t::HashEngine<Tag>,
    h: sha384::HashEngine,
    i: sha512::HashEngine,
    j: sha512_256::HashEngine,
    k: siphash24::HashEngine,
    l: sha3_256::HashEngine,
}

impl Engines {
    fn new_sha256() -> Self {
        Self {
            a: hash160::HashEngine::new(),
            b: hmac::HmacEngine::<sha256::HashEngine>::new(&[]),
            c: ripemd160::HashEngine::new(),
            d: sha1::HashEngine::new(),
            e: sha256::HashEngine::new(),
            f: sha256d::HashEngine::new(),
            g: sha256t::Hash::<Tag>::engine(),
            h: sha384::HashEngine::new(),
            i: sha512::HashEngine::new(),
            j: sha512_256::HashEngine::new(),
            k: siphash24::HashEngine::with_keys(0, 0),
            l: sha3_256::HashEngine::new(),
        }
    }
}

/// Public structs that are not hashes, engines, or errors.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)] // C-COMMON-TRAITS
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct OtherStructs {
    a: sha256::Midstate,
    // There is no way to construct a `siphash24::State` so we cannot directly
    // test it but `siphash24::HashEngine` includes one so `Engines` implicitly
    // tests it (e.g. `Debug` and `Clone`).
    //
    // b: siphash24::State,

    // Don't worry about including a tag because its tested in `primitives`.
}

impl OtherStructs {
    fn new() -> Self { Self { a: sha256::Midstate::new(TEST_MIDSTATE, 0) } }
}

/// All hash engine types that implement `Default`.
#[derive(Default)]
struct Default {
    a: hash160::HashEngine,
    b: ripemd160::HashEngine,
    c: sha1::HashEngine,
    d: sha256::HashEngine,
    e: sha256d::HashEngine,
    f: sha256t::HashEngine<Tag>,
    g: sha384::HashEngine,
    h: sha512::HashEngine,
    i: sha512_256::HashEngine,
    j: sha3_256::HashEngine,
}

/// Hash types that require a key.
struct Keyed<T: Hash> {
    a: Hmac<T>,
    l: siphash24::Hash,
}

/// A struct that includes all public error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    b: hkdf::MaxLengthError,
    c: sha256::MidstateError,
}

#[test]
fn api_can_use_modules_from_crate_root() {
    use bitcoin_hashes::{
        hash160, hkdf, hmac, muhash, ripemd160, sha1, sha256, sha256d, sha256t, sha384, sha512,
        sha512_256, siphash24,
    };
}

#[test]
fn api_can_use_alias_from_crate_root() {
    use bitcoin_hashes::{
        Hash160, Hkdf, Hmac, MuHash, Ripemd160, Sha1, Sha256, Sha256d, Sha256t, Sha384, Sha512,
        Sha512_256, Siphash24,
    };
}

// `Debug` representation is never empty (C-DEBUG-NONEMPTY).
#[test]
fn api_all_non_error_types_have_non_empty_debug() {
    macro_rules! check_debug {
        ($t:tt; $($field:tt),* $(,)?) => {
            $(
                let debug = format!("{:?}", $t.$field);
                assert!(!debug.is_empty());
            )*
        }
    }

    let t = Hashes::<Sha256>::new_sha256();
    check_debug!(t; a, c, d, e, f, g, h, i, j, k, l);

    // This tests `Debug` on `Hkdf` but not for all `HashEngine` types.
    let t = Hkdf::<sha256::HashEngine>::new(&[], &[]);
    let debug = format!("{:?}", t);
    assert!(!debug.is_empty());

    let t = Engines::new_sha256();
    check_debug!(t; a, c, d, e, f, g, h, i, j, k);

    let t = OtherStructs::new();
    check_debug!(t; a);
}

#[test]
fn all_types_implement_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Hashes<Sha256>>();
    assert_sync::<Hashes<Sha256>>();
    assert_send::<Engines>();
    assert_sync::<Engines>();
    assert_send::<OtherStructs>();
    assert_sync::<OtherStructs>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}
