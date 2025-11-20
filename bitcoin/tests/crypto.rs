use bitcoin::crypto::key::{FromWifError, InvalidWifCompressionFlagError, PrivateKey, PublicKey};
use bitcoin::{Address, NetworkKind};

#[test]
fn key_derivation() {
    // mainnet compressed WIF with invalid compression flag.
    let sk = PrivateKey::from_wif("L2x4uC2YgfFWZm9tF4pjDnVR6nJkheizFhEr2KvDNnTEmEqVzPJY");
    assert!(matches!(
        sk,
        Err(FromWifError::InvalidWifCompressionFlag(InvalidWifCompressionFlagError { .. }))
    ));

    // FIXME: The write_err macro is not working as advertised because this should print the inner error also
    //         write!(f, "invalid WIF compression flag. Expected a 0x01 byte at the end of the key but found: {}", self.invalid)
    //
    // #[cfg(feature = "std")]
    // println!("error: {}", sk.unwrap_err());
    // panic!("should have printed the inner error");
    // assert!(format!("{}", sk.unwrap_err()).contains("49"));

    // testnet compressed
    let sk = PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
    assert_eq!(sk.network, NetworkKind::Test);
    assert!(sk.compressed);
    assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

    let pk = Address::p2pkh(sk.public_key(), sk.network);
    assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

    // test string conversion
    assert_eq!(&sk.to_string(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
    let sk_str =
        "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy".parse::<PrivateKey>().unwrap();
    assert_eq!(&sk.to_wif(), &sk_str.to_wif());

    // mainnet uncompressed
    let sk = PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
    assert_eq!(sk.network, NetworkKind::Main);
    assert!(!sk.compressed);
    assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

    let mut pk = sk.public_key();
    assert!(!pk.compressed);
    assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
    assert_eq!(pk, "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133"
               .parse::<PublicKey>().unwrap());
    let addr = Address::p2pkh(pk, sk.network);
    assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
    pk.compressed = true;
    assert_eq!(
        &pk.to_string(),
        "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
    );
    assert_eq!(
        pk,
        "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse::<PublicKey>()
            .unwrap()
    );
}
