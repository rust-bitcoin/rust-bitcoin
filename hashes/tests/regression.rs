//! Regression tests for each hash type.

use bitcoin_hashes::{
    hash160, ripemd160, sha1, sha256, sha256d, sha256t, sha384, sha512, sha512_256, siphash24,
    GeneralHash as _, HashEngine as _, Hmac, HmacEngine,
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
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::new([0xab; 32], 64);
        sha256::HashEngine::from_midstate(midstate)
    }
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
fn regression_hmac_sha256_with_default_key() {
    let hash = Hmac::<sha256::Hash>::hash(DATA.as_bytes());
    let got = format!("{}", hash);
    let want = "58cc7ed8567bd86eba61f7ed2d5a4edab1774dc10488e57de2eb007a2d9ae82d";
    assert_eq!(got, want);
}

#[test]
fn regression_hmac_sha512_with_default_key() {
    let hash = Hmac::<sha512::Hash>::hash(DATA.as_bytes());
    let got = format!("{}", hash);
    let want = "5f5db2f3e1178bf19af5db38a0ed04dc5bc52d641648542886eea9b6bbec0db658ed7a5799ca18f5bc1949f39d24151a32990ee85974e40bb8a35e2288f494ce";
    assert_eq!(got, want);
}

#[test]
fn regression_hmac_sha256_with_key() {
    let mut engine = HmacEngine::<sha256::Hash>::new(HMAC_KEY);
    engine.input(DATA.as_bytes());
    let hash = Hmac::from_engine(engine);

    let got = format!("{}", hash);
    let want = "d159cecaf4adf90b6a641bab767e4817d3a51c414acea3682686c35ec0b37b52";
    assert_eq!(got, want);
}

#[test]
fn regression_hmac_sha512_with_key() {
    let mut engine = HmacEngine::<sha512::Hash>::new(HMAC_KEY);
    engine.input(DATA.as_bytes());
    let hash = Hmac::from_engine(engine);

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
