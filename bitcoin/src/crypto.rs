// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.

pub mod ecdsa {
    //! ECDSA Bitcoin signatures.
    //!
    //! This module provides ECDSA signatures used by Bitcoin that can be roundtrip (de)serialized.
    pub use primitives::ecdsa::*;
}

pub mod key {
    //! Bitcoin keys.
    //!
    //! This module provides keys used in Bitcoin that can be roundtrip (de)serialized.
    pub use primitives::key::*;

    #[cfg(test)]
    mod tests {
        use core::str::FromStr;

        use super::*;
        use crate::{Address, NetworkKind};
        
        #[test]
        fn test_key_derivation() {
            // testnet compressed
            let sk =
                PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
            assert_eq!(sk.network, NetworkKind::Test);
            assert!(sk.compressed);
            assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

            let secp = Secp256k1::new();
            let pk = Address::p2pkh(sk.public_key(&secp), sk.network);
            assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

            // test string conversion
            assert_eq!(&sk.to_string(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
            let sk_str =
                PrivateKey::from_str("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
            assert_eq!(&sk.to_wif(), &sk_str.to_wif());

            // mainnet uncompressed
            let sk =
                PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
            assert_eq!(sk.network, NetworkKind::Main);
            assert!(!sk.compressed);
            assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

            let secp = Secp256k1::new();
            let mut pk = sk.public_key(&secp);
            assert!(!pk.compressed);
            assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
            assert_eq!(pk, PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap());
            let addr = Address::p2pkh(pk, sk.network);
            assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
            pk.compressed = true;
            assert_eq!(
                &pk.to_string(),
                "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            );
            assert_eq!(
                pk,
                PublicKey::from_str(
                    "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
                )
                    .unwrap()
            );
        }
    }
}

pub mod sighash {
    //! Signature hash implementation (used in transaction signing).
    //!
    //! Efficient implementation of the algorithm to compute the message to be signed according to
    //! [Bip341](https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki),
    //! [Bip143](https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki)
    //! and legacy (before Bip143).
    //!
    //! Computing signature hashes is required to sign a transaction and this module is designed to
    //! handle its complexity efficiently. Computing these hashes is as simple as creating
    //! [`SighashCache`] and calling its methods.
    pub use primitives::sighash::*;
}

// This stuff is publicly re-exported from `src/taproot.rs`.
pub(crate) mod taproot {
    //! Bitcoin taproot keys.
    //!
    //! This module provides taproot keys used in Bitcoin (including reexporting secp256k1 keys).
    pub use primitives::taproot::*;
}
