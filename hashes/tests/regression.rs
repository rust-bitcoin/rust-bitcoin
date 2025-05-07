//! Regression tests for each hash type.
//!
//! Note that if `bitcoin-io` is enabled then we get more regression-like testing from `./io.rs`.
//!
//! Test input data and expected hashes is the same as in `io/src/hash.rs`.

#![cfg(feature = "hex")]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)`instead of enforcing `format!("{x}")`

use bitcoin_hashes::{
    hash160, ripemd160, sha1, sha256, sha256d, sha256t, sha384, sha512, sha512_256, siphash24,
    HashEngine as _, HmacEngine,
};

const DATA: &str = "arbitrary data to hash as a regression test";
const HMAC_KEY: &[u8] = b"some key";

macro_rules! impl_regression_test {
    ($($test_name:ident, $module:ident, $want:literal);* $(;)?) => {
        $(
            #[test]
            fn $test_name() {
                let hash = $module::Hash::hash(DATA.as_bytes());
                let got = format!("{}", hash);
                assert_eq!(got, $want);
            }
        )*
    }
}

impl_regression_test! {
    regression_hash160, hash160, "a17909f6d5373b0085c4180ba207126e5040f74d";
    regression_ripemd160, ripemd160, "e6801701c77a1cd85662335258c7869631b4a9a8";
    regression_sha1, sha1, "e1e81eeabadafa3d5d41cc3f405385426b0f47fd";
    regression_sha256, sha256, "d291c6c5a07fa1d9315cdae090ebe14169fbe0a219cd55a48d0d2104eab6ec51";
    regression_sha256d, sha256d, "93a743b022290bde3233a619b21aaebe06c5cf5cc959464c41be35711e37731b";
    regression_sha384, sha384, "f545bd83d297978d47a7f26b858a54188499dfb4d7d570a6a2362c765031d57a29d7e002df5e34d184e70b65a4f47153";
    regression_sha512, sha512, "057d0a37e9e0ac9a93acde0752748da059a27bcf946c7af00692ac1a95db8d21f965f40af22efc4710f100f8d3e43f79f77b1f48e1e400a95b7344b7bc0dfd10";
    regression_sha512_256, sha512_256, "e204244c429b5bca037a2a8a6e7ed8a42b808ceaff182560840bb8c5c8e9a2ec";
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct RegHashTag;

impl sha256t::Tag for RegHashTag {
    const MIDSTATE: sha256::Midstate = sha256::Midstate::new([0xab; 32], 64);
}

type RegHash = sha256t::Hash<RegHashTag>;

#[test]
fn regression_sha256t() {
    let hash = RegHash::hash(DATA.as_bytes());
    let got = format!("{}", hash);
    let want = "17db326d7c13867376ccca1f8a211377be3cbeaeb372f167822284866ddf14ca";
    assert_eq!(got, want);
}

#[test]
fn regression_hmac_sha256_with_key() {
    let mut engine = HmacEngine::<sha256::HashEngine>::new(HMAC_KEY);
    engine.input(DATA.as_bytes());
    let hash = engine.finalize();

    let got = format!("{}", hash);
    let want = "d159cecaf4adf90b6a641bab767e4817d3a51c414acea3682686c35ec0b37b52";
    assert_eq!(got, want);
}

#[test]
fn regression_hmac_sha512_with_key() {
    let mut engine = HmacEngine::<sha512::HashEngine>::new(HMAC_KEY);
    engine.input(DATA.as_bytes());
    let hash = engine.finalize();

    let got = format!("{}", hash);
    let want = "8511773748f89ba22c07fb3a2981a12c1823695119de41f4a62aead6b848bd34939acf16475c35ed7956114fead3e794cc162ecd35e447a4dabc3227d55f757b";
    assert_eq!(got, want);
}

#[test]
fn regression_siphash24_with_key() {
    let mut engine = siphash24::HashEngine::with_keys(0, 0);
    engine.input(DATA.as_bytes());
    let hash = siphash24::Hash::from_engine(engine);

    let got = format!("{}", hash);
    let want = "e823ed82311d601a";
    assert_eq!(got, want);
}

#[test]
fn regression_sha256_hash_again() {
    let hash = sha256::Hash::hash(b"Don't explain your philosophy. Embody it.");
    let again = hash.hash_again();

    let got = format!("{}", again);
    let want = "28273103bcd88ab99e2b1007174770ff3f0ea91ee4b3ac942879ed1a2d264b4c";
    assert_eq!(got, want);
}
