// SPDX-License-Identifier: CC0-1.0

//! Primitive decoders.

use super::Decoder;

/// Not enough bytes given to decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnexpectedEof {
    /// Number of bytes missing to complete decoder.
    pub missing: usize,
}

impl core::fmt::Display for UnexpectedEof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not enough bytes for decoder, {} more bytes required", self.missing)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnexpectedEof {}

/// A decoder that expects exactly N bytes and returns them as an array.
pub struct ArrayDecoder<const N: usize> {
    buffer: [u8; N],
    bytes_written: usize,
}

impl<const N: usize> ArrayDecoder<N> {
    /// Creates a new array decoder that expects exactly N bytes.
    pub fn new() -> Self {
        Self { buffer: [0; N], bytes_written: 0 }
    }
}

impl<const N: usize> Default for ArrayDecoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Decoder for ArrayDecoder<N> {
    type Output = [u8; N];
    type Error = UnexpectedEof;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        let remaining_space = N - self.bytes_written;
        let copy_len = bytes.len().min(remaining_space);

        if copy_len > 0 {
            self.buffer[self.bytes_written..self.bytes_written + copy_len]
                .copy_from_slice(&bytes[..copy_len]);
            self.bytes_written += copy_len;
            // Advance the slice reference to consume the bytes.
            *bytes = &bytes[copy_len..];
        }

        Ok(())
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        if self.bytes_written == N {
            Ok(self.buffer)
        } else {
            Err(UnexpectedEof { missing: N - self.bytes_written })
        }
    }
}
