// SPDX-License-Identifier: CC0-1.0

//! # `ChaCha20` - `Poly1305`
//!
//! Combine the `ChaCha20` stream cipher with the `Poly1305` message authentication code
//! to form an authenticated encryption with additional data (AEAD) algorithm.

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::inline_always)] // Not sure yet if we should give up the inline always, possible that the LLVM knows better.
#![cfg_attr(chacha20_poly1305_fuzz, allow(dead_code, unused_imports))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod chacha20;
pub mod poly1305;

use chacha20::ChaCha20;
use poly1305::Poly1305;

pub use self::chacha20::{Key, Nonce};
#[doc(no_inline)]
pub use self::error::Error;

/// Zero array for padding slices.
const ZEROES: [u8; 16] = [0u8; 16];

/// Encrypt and decrypt content along with an authentication tag.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChaCha20Poly1305 {
    key: Key,
    nonce: Nonce,
}

impl ChaCha20Poly1305 {
    /// Make a new instance of a `ChaCha20Poly1305` AEAD.
    pub const fn new(key: Key, nonce: Nonce) -> Self { Self { key, nonce } }

    /// Encrypt content in place and return the `Poly1305` 16-byte authentication tag.
    ///
    /// # Parameters
    ///
    /// - `content` - the plaintext to be encrypted in place.
    /// - `aad`     - the optional metadata covered by the authentication tag.
    ///
    /// # Returns
    ///
    /// The 16-byte authentication tag.
    pub fn encrypt(self, content: &mut [u8], aad: Option<&[u8]>) -> [u8; 16] {
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
        chacha.apply_keystream(content);
        #[cfg(not(chacha20_poly1305_fuzz))]
        let poly_key = {
            let keystream = chacha.get_keystream(0);
            let mut k = [0u8; 32];
            k.copy_from_slice(&keystream[..32]);
            k
        };
        #[cfg(chacha20_poly1305_fuzz)]
        let poly_key = self.key.0;
        let mut poly = Poly1305::new(poly_key);
        let aad = aad.unwrap_or(&[]);
        // AAD and ciphertext are padded if not 16-byte aligned.
        poly.input(aad);
        let aad_overflow = aad.len() % 16;
        if aad_overflow > 0 {
            poly.input(&ZEROES[0..(16 - aad_overflow)]);
        }

        poly.input(content);
        let text_overflow = content.len() % 16;
        if text_overflow > 0 {
            poly.input(&ZEROES[0..(16 - text_overflow)]);
        }

        let len_buffer = encode_lengths(aad.len() as u64, content.len() as u64);
        poly.input(&len_buffer);
        poly.tag()
    }

    /// Decrypt the ciphertext in place if authentication tag is correct.
    ///
    /// # Parameters
    ///
    /// - `content` - Ciphertext to be decrypted in place.
    /// - `tag`     - 16-byte authentication tag.
    /// - `aad`     - Optional metadata covered by the authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnauthenticatedAdditionalData`] if the computed authentication tag does
    /// not match the provided tag.
    pub fn decrypt(
        self,
        content: &mut [u8],
        tag: [u8; 16],
        aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        #[cfg(not(chacha20_poly1305_fuzz))]
        let poly_key = {
            let chacha = ChaCha20::new_from_block(self.key, self.nonce, 0);
            let keystream = chacha.get_keystream(0);
            let mut k = [0u8; 32];
            k.copy_from_slice(&keystream[..32]);
            k
        };
        #[cfg(chacha20_poly1305_fuzz)]
        let poly_key = self.key.0;
        let mut poly = Poly1305::new(poly_key);
        let aad = aad.unwrap_or(&[]);
        poly.input(aad);
        // AAD and ciphertext are padded if not 16-byte aligned.
        let aad_overflow = aad.len() % 16;
        if aad_overflow > 0 {
            poly.input(&ZEROES[0..(16 - aad_overflow)]);
        }
        poly.input(content);
        let msg_overflow = content.len() % 16;
        if msg_overflow > 0 {
            poly.input(&ZEROES[0..(16 - msg_overflow)]);
        }

        let len_buffer = encode_lengths(aad.len() as u64, content.len() as u64);
        poly.input(&len_buffer);
        let derived_tag = poly.tag();

        if constant_time_eq(&derived_tag, &tag) {
            let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
            chacha.apply_keystream(content);
            Ok(())
        } else {
            Err(Error::UnauthenticatedAdditionalData)
        }
    }
}

/// Performs a constant-time equality check between two 16-byte arrays.
/// ensuring that the comparison time does not leak information about the contents.
#[inline]
fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut res = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

/// AAD and content lengths are each encoded in 8-bytes.
fn encode_lengths(aad_len: u64, content_len: u64) -> [u8; 16] {
    let aad_len_bytes = aad_len.to_le_bytes();
    let content_len_bytes = content_len.to_le_bytes();
    let mut len_buffer = [0u8; 16];
    let (aad_len_buffer, content_len_buffer) = len_buffer.split_at_mut(8);
    aad_len_buffer.copy_from_slice(&aad_len_bytes[..]);
    content_len_buffer.copy_from_slice(&content_len_bytes[..]);

    len_buffer
}

/// Error types for the `ChaCha20Poly1305` AEAD.
pub mod error {
    use core::fmt;

    /// Errors encrypting and decrypting messages with `ChaCha20` and `Poly1305` authentication tags.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum Error {
        /// Additional data showing up when it is not expected.
        UnauthenticatedAdditionalData,
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::UnauthenticatedAdditionalData => write!(f, "Unauthenticated aad."),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::UnauthenticatedAdditionalData => None,
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use hex::{hex, DisplayHex as _};

    use super::*;

    #[cfg(not(chacha20_poly1305_fuzz))]
    #[test]
    fn rfc7539() {
        let mut message = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let key =
            Key::new(hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));
        let nonce = Nonce::new(hex!("070000004041424344454647"));
        let cipher = ChaCha20Poly1305::new(key, nonce);
        let tag = cipher.encrypt(&mut message, Some(&aad));

        let mut buffer = [0u8; 130];
        buffer[..message.len()].copy_from_slice(&message);
        buffer[message.len()..].copy_from_slice(&tag);

        assert_eq!(&buffer.to_lower_hex_string(), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    }

    #[cfg(not(chacha20_poly1305_fuzz))]
    #[test]
    fn test_constant_time_eq() {
        let tag_a = [0x42u8; 16];
        let tag_b = [0x42u8; 16];
        let tag_c = [0x00u8; 16];

        // full equality
        assert!(constant_time_eq(&tag_a, &tag_b));

        // full difference
        assert!(!constant_time_eq(&tag_a, &tag_c));

        // edge case  - single byte diff
        let mut tag_d = tag_a;

        // first byte diff
        tag_d[0] ^= 1;
        assert!(!constant_time_eq(&tag_a, &tag_d));

        // last byte only diff
        tag_d = tag_a;
        tag_d[15] ^= 1;
        assert!(!constant_time_eq(&tag_a, &tag_d));

        // mid byte diff
        tag_d = tag_a;
        tag_d[7] ^= 0xff;
        assert!(!constant_time_eq(&tag_a, &tag_d));
    }
}
