// SPDX-License-Identifier: CC0-1.0

//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//!
//! Implementation based on RFC5869, but the interface is scoped
//! to BIP324's requirements.

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use crate::{GeneralHash, HashEngine, Hmac, HmacEngine};

/// Output keying material max length multiple.
const MAX_OUTPUT_BLOCKS: usize = 255;

/// Size of output exceeds maximum length allowed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MaxLengthError {
    max: usize,
}

impl fmt::Display for MaxLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "exceeds {} byte max output material limit", self.max)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MaxLengthError {}

/// HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
pub struct Hkdf<T: GeneralHash> {
    /// Pseudorandom key based on the extract step.
    prk: Hmac<T>,
}

impl<T: GeneralHash> Hkdf<T>
where
    <T as GeneralHash>::Engine: Default,
{
    /// Initialize a HKDF by performing the extract step.
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let mut hmac_engine: HmacEngine<T> = HmacEngine::new(salt);
        hmac_engine.input(ikm);
        Self { prk: Hmac::from_engine(hmac_engine) }
    }

    /// Expand the key to generate output key material in okm.
    ///
    /// Expand may be called multiple times to derive multiple keys,
    /// but the info must be independent from the ikm for security.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), MaxLengthError> {
        // Length of output keying material in bytes must be less than 255 * hash length.
        if okm.len() > (MAX_OUTPUT_BLOCKS * T::LEN) {
            return Err(MaxLengthError { max: MAX_OUTPUT_BLOCKS * T::LEN });
        }

        // Counter starts at "1" based on RFC5869 spec and is committed to in the hash.
        let mut counter = 1u8;
        // Ceiling calculation for the total number of blocks (iterations) required for the expand.
        let total_blocks = (okm.len() + T::LEN - 1) / T::LEN;

        while counter <= total_blocks as u8 {
            let mut hmac_engine: HmacEngine<T> = HmacEngine::new(self.prk.as_ref());

            // First block does not have a previous block,
            // all other blocks include last block in the HMAC input.
            if counter != 1u8 {
                let previous_start_index = (counter as usize - 2) * T::LEN;
                let previous_end_index = (counter as usize - 1) * T::LEN;
                hmac_engine.input(&okm[previous_start_index..previous_end_index]);
            }
            hmac_engine.input(info);
            hmac_engine.input(&[counter]);

            let t = Hmac::from_engine(hmac_engine);
            let start_index = (counter as usize - 1) * T::LEN;
            // Last block might not take full hash length.
            let end_index =
                if counter == (total_blocks as u8) { okm.len() } else { counter as usize * T::LEN };

            okm[start_index..end_index].copy_from_slice(&t.as_ref()[0..(end_index - start_index)]);

            counter += 1;
        }

        Ok(())
    }

    /// Expand the key to specified length.
    ///
    /// Expand may be called multiple times to derive multiple keys,
    /// but the info must be independent from the ikm for security.
    #[cfg(feature = "alloc")]
    pub fn expand_to_len(&self, info: &[u8], len: usize) -> Result<Vec<u8>, MaxLengthError> {
        let mut okm = vec![0u8; len];
        self.expand(info, &mut okm)?;
        Ok(okm)
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use hex::prelude::{DisplayHex, FromHex};

    use super::*;
    use crate::sha256;

    #[test]
    fn test_rfc5869_basic() {
        let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
        let ikm = Vec::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let hkdf = Hkdf::<sha256::Hash>::new(&salt, &ikm);
        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();

        assert_eq!(
            okm.to_lower_hex_string(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn test_rfc5869_longer_inputs_outputs() {
        let salt = Vec::from_hex(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        ).unwrap();
        let ikm = Vec::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        ).unwrap();
        let info = Vec::from_hex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ).unwrap();

        let hkdf = Hkdf::<sha256::Hash>::new(&salt, &ikm);
        let mut okm = [0u8; 82];
        hkdf.expand(&info, &mut okm).unwrap();

        assert_eq!(
            okm.to_lower_hex_string(),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
    }

    #[test]
    fn test_too_long_okm() {
        let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
        let ikm = Vec::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let hkdf = Hkdf::<sha256::Hash>::new(&salt, &ikm);
        let mut okm = [0u8; 256 * 32];
        let e = hkdf.expand(&info, &mut okm);

        assert!(e.is_err());
    }

    #[test]
    fn test_short_okm() {
        let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
        let ikm = Vec::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let hkdf = Hkdf::<sha256::Hash>::new(&salt, &ikm);
        let mut okm = [0u8; 1];
        hkdf.expand(&info, &mut okm).unwrap();

        assert_eq!(okm.to_lower_hex_string(), "3c");
    }

    #[test]
    fn test_alloc_wrapper() {
        let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
        let ikm = Vec::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let hkdf = Hkdf::<sha256::Hash>::new(&salt, &ikm);
        let okm = hkdf.expand_to_len(&info, 42).unwrap();

        assert_eq!(
            okm.to_lower_hex_string(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
