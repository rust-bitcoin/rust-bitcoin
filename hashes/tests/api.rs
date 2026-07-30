// SPDX-License-Identifier: CC0-1.0

//! Test the API surface (not functionality) of `bitcoin_hashes`.
//!
//! See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html) and the [rust-bitcoin policies](../../docs/policy.md).

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(deprecated)]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

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

// Arbitrary midstate value; taken from as SHA256t unit tests.
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
    /// A concrete SHA256t hash type so we don't have to use generics.
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

/// C-DEBUG-NONEMPTY: Tests that all public non-error types have non-empty Debug.
#[test]
fn c_debug_nonempty() {
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

/// C-DEBUG-NONEMPTY: Tests that all public error types have non-empty Debug.
#[test]
fn c_debug_nonempty_errors() {
    // HKDF is capped at 255 output blocks, so one byte past that limit must error.
    let mut okm = vec![0_u8; 255 * 32 + 1];
    let err = Hkdf::<sha256::HashEngine>::new(&[], &[]).expand(&[], &mut okm).unwrap_err();
    let debug = format!("{:?}", err);
    assert!(!debug.is_empty());

    let mut engine = sha256::HashEngine::new();
    engine.input(&[0xab]);
    let err = engine.midstate().unwrap_err();
    let debug = format!("{:?}", err);
    assert!(!debug.is_empty());
}

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn c_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Hashes<Sha256>>();
    assert_sync::<Hashes<Sha256>>();
    assert_send::<Hkdf<sha256::HashEngine>>();
    assert_sync::<Hkdf<sha256::HashEngine>>();
    assert_send::<Engines>();
    assert_sync::<Engines>();
    assert_send::<OtherStructs>();
    assert_sync::<OtherStructs>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}

/// C-GOOD-ERR: Tests that all public error types implement [`std::error::Error`].
#[cfg(feature = "std")]
#[test]
fn c_good_err_error() {
    fn assert_error<T: std::error::Error>() {}

    assert_error::<hkdf::MaxLengthError>();
    assert_error::<sha256::MidstateError>();
}

/// C-OBJECT: Tests that traits are object-safe where appropriate.
#[test]
fn c_object() {
    // use bitcoin_hashes::{sha256t, HashEngine, Hash, IsByteArray};

    // struct Traits {
    //     // These traits are explicitly not dyn compatible.
    //     a: Box<dyn HashEngine>,
    //     b: Box<dyn Hash>,
    //     c: Box<dyn IsByteArray>,
    //     d: Box<dyn sha256t::Tag>,
    // }
}

/// C-SERDE: Tests that serde traits are implemented where expected.
#[test]
#[cfg(feature = "serde")]
fn c_serde() {
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

    assert_serde::<Sha256>();
    assert_serde::<Sha256d>();
    assert_serde::<Hash160>();
    assert_serde::<Ripemd160>();
    assert_serde::<Sha1>();
    assert_serde::<Sha384>();
    assert_serde::<Sha512>();
    assert_serde::<Sha512_256>();
    assert_serde::<Sha3_256>();
}

/// P-CONSISTENT-EXPORTS: Tests that modules are exported from the crate root.
#[test]
fn p_consistent_exports_modules() {
    use bitcoin_hashes::{
        hash160, hkdf, hmac, muhash, ripemd160, sha1, sha256, sha256d, sha256t, sha384, sha512,
        sha512_256, siphash24,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that type aliases are exported from the crate root.
#[test]
fn p_consistent_exports_aliases() {
    use bitcoin_hashes::{
        Hash160, Hkdf, Hmac, MuHash, Ripemd160, Sha1, Sha256, Sha256d, Sha256t, Sha384, Sha512,
        Sha512_256, Siphash24,
    };
}

/// P-ARBITRARY: Tests that public types implement `Arbitrary`.
#[test]
#[cfg(feature = "arbitrary")]
fn p_arbitrary() {
    fn assert_arbitrary<T: for<'a> Arbitrary<'a>>() {}

    assert_arbitrary::<Sha256>();
    assert_arbitrary::<Sha256d>();
}
