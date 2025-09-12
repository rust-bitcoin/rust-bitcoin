// SPDX-License-Identifier: CC0-1.0

//! The ChaCha20 stream cipher from RFC8439.

use core::ops::BitXor;

/// The first four words (32-bit) of the ChaCha stream cipher state are constants.
const WORD_1: u32 = 0x61707865;
const WORD_2: u32 = 0x3320646e;
const WORD_3: u32 = 0x79622d32;
const WORD_4: u32 = 0x6b206574;

/// The cipher's block size is 64 bytes.
const CHACHA_BLOCKSIZE: usize = 64;

/// A 256-bit secret key shared by the parties communicating.
#[derive(Clone, Copy)]
pub struct Key([u8; 32]);

impl Key {
    /// Constructs a new key.
    pub const fn new(key: [u8; 32]) -> Self { Key(key) }
}

/// A 96-bit initialization vector (IV), or nonce.
#[derive(Clone, Copy)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Constructs a new nonce.
    pub const fn new(nonce: [u8; 12]) -> Self { Nonce(nonce) }
}

// Const validation trait for compile time check with max of 3.
trait UpTo3<const N: u32> {}

impl UpTo3<0> for () {}
impl UpTo3<1> for () {}
impl UpTo3<2> for () {}
impl UpTo3<3> for () {}

/// A SIMD-friendly structure which holds 25% of the cipher state.
///
/// The cipher's quarter round function is the bulk of its work
/// and there are large performance gains to be had if the function
/// leverages SIMD instructions on architectures which support them. Because
/// the algorithm allows for the cipher's state to be operated on in
/// parallel (each round only touches a quarter of the state), then theoretically
/// the parallel SIMD instructions should be used. But sometimes the
/// compiler needs a few hints to ensure it recognizes a "vectorizable" function.
/// That is the goal of this type, which clearly breaks the state up into four
/// chunks and exposes functions which align with SIMD lanes.
///
/// This type is attempting to be as close as possible to the experimental [`core::simd::u32x4`]
/// which at this time is feature gated and well beyond the project's MSRV. But ideally
/// an easy transition can be made in the future.
///
/// A few SIMD relevant design choices:
///    * Heavy use of inline functions to help the compiler recognize vectorizable sections.
///    * For-each loops are easy for the compiler to recognize as vectorizable.
///    * The type is a based on an array instead of tuple since the heterogeneous
///      nature of tuples can confuse the compiler into thinking it is not vectorizable.
///
/// In the future, a "blacklist" for the alignment option might be useful to
/// disable it on architectures which definitely do not support SIMD in order to avoid
/// needless memory inefficiencies.
#[derive(Clone, Copy, PartialEq)]
struct U32x4([u32; 4]);

impl U32x4 {
    #[inline(always)]
    fn wrapping_add(self, rhs: Self) -> Self {
        let mut result = [0u32; 4];
        (0..4).for_each(|i| {
            result[i] = self.0[i].wrapping_add(rhs.0[i]);
        });
        U32x4(result)
    }

    #[inline(always)]
    fn rotate_left(self, n: u32) -> Self {
        let mut result = [0u32; 4];
        (0..4).for_each(|i| {
            result[i] = self.0[i].rotate_left(n);
        });
        U32x4(result)
    }

    #[inline(always)]
    fn rotate_elements_left<const N: u32>(self) -> Self
    where
        (): UpTo3<N>,
    {
        match N {
            1 => U32x4([self.0[1], self.0[2], self.0[3], self.0[0]]),
            2 => U32x4([self.0[2], self.0[3], self.0[0], self.0[1]]),
            3 => U32x4([self.0[3], self.0[0], self.0[1], self.0[2]]),
            _ => self, // Rotate by 0 is a no-op.
        }
    }

    #[inline(always)]
    fn rotate_elements_right<const N: u32>(self) -> Self
    where
        (): UpTo3<N>,
    {
        match N {
            1 => U32x4([self.0[3], self.0[0], self.0[1], self.0[2]]),
            2 => U32x4([self.0[2], self.0[3], self.0[0], self.0[1]]),
            3 => U32x4([self.0[1], self.0[2], self.0[3], self.0[0]]),
            _ => self, // Rotate by 0 is a no-op.
        }
    }

    #[inline(always)]
    fn to_le_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        (0..4).for_each(|i| {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&self.0[i].to_le_bytes());
        });
        bytes
    }
}

impl BitXor for U32x4 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        let mut result = [0u32; 4];
        (0..4).for_each(|i| {
            result[i] = self.0[i] ^ rhs.0[i];
        });
        U32x4(result)
    }
}

/// The 512-bit cipher state is chunk'd up into 16 32-bit words.
///
/// The 16 words can be visualized as a 4x4 matrix:
///
///   0   1   2   3
///   4   5   6   7
///   8   9  10  11
///  12  13  14  15
#[derive(Clone, Copy, PartialEq)]
struct State {
    matrix: [U32x4; 4],
}

impl State {
    /// New prepared state.
    const fn new(key: Key, nonce: Nonce, count: u32) -> Self {
        // Hardcoding indexes to keep the function const.
        let k0 = u32::from_le_bytes([key.0[0], key.0[1], key.0[2], key.0[3]]);
        let k1 = u32::from_le_bytes([key.0[4], key.0[5], key.0[6], key.0[7]]);
        let k2 = u32::from_le_bytes([key.0[8], key.0[9], key.0[10], key.0[11]]);
        let k3 = u32::from_le_bytes([key.0[12], key.0[13], key.0[14], key.0[15]]);
        let k4 = u32::from_le_bytes([key.0[16], key.0[17], key.0[18], key.0[19]]);
        let k5 = u32::from_le_bytes([key.0[20], key.0[21], key.0[22], key.0[23]]);
        let k6 = u32::from_le_bytes([key.0[24], key.0[25], key.0[26], key.0[27]]);
        let k7 = u32::from_le_bytes([key.0[28], key.0[29], key.0[30], key.0[31]]);

        let n0 = u32::from_le_bytes([nonce.0[0], nonce.0[1], nonce.0[2], nonce.0[3]]);
        let n1 = u32::from_le_bytes([nonce.0[4], nonce.0[5], nonce.0[6], nonce.0[7]]);
        let n2 = u32::from_le_bytes([nonce.0[8], nonce.0[9], nonce.0[10], nonce.0[11]]);

        State {
            matrix: [
                U32x4([WORD_1, WORD_2, WORD_3, WORD_4]),
                U32x4([k0, k1, k2, k3]),
                U32x4([k4, k5, k6, k7]),
                U32x4([count, n0, n1, n2]),
            ],
        }
    }

    /// Four quarter rounds performed on the entire state of the cipher in a vectorized SIMD friendly fashion.
    #[inline(always)]
    fn quarter_round(a: U32x4, b: U32x4, c: U32x4, d: U32x4) -> [U32x4; 4] {
        let a = a.wrapping_add(b);
        let d = d.bitxor(a).rotate_left(16);

        let c = c.wrapping_add(d);
        let b = b.bitxor(c).rotate_left(12);

        let a = a.wrapping_add(b);
        let d = d.bitxor(a).rotate_left(8);

        let c = c.wrapping_add(d);
        let b = b.bitxor(c).rotate_left(7);

        [a, b, c, d]
    }

    /// Performs a round on "columns" and then "diagonals" of the state.
    ///
    /// The column quarter rounds are made up of indexes: `[0,4,8,12]`, `[1,5,9,13]`, `[2,6,10,14]`, `[3,7,11,15]`.
    /// The diagonals quarter rounds are made up of indexes: `[0,5,10,15]`, `[1,6,11,12]`, `[2,7,8,13]`, `[3,4,9,14]`.
    ///
    /// The underlying quarter_round function is vectorized using the
    /// u32x4 type in order to perform 4 quarter round functions at the same time.
    /// This is a little more difficult to read, but it gives the compiler
    /// a strong hint to use the performant SIMD instructions.
    #[inline(always)]
    fn double_round(state: [U32x4; 4]) -> [U32x4; 4] {
        let [mut a, mut b, mut c, mut d] = state;

        // Column round.
        [a, b, c, d] = Self::quarter_round(a, b, c, d);

        // Diagonal round (with rotations).
        b = b.rotate_elements_left::<1>();
        c = c.rotate_elements_left::<2>();
        d = d.rotate_elements_left::<3>();
        [a, b, c, d] = Self::quarter_round(a, b, c, d);
        // Rotate the words back into their normal positions.
        b = b.rotate_elements_right::<1>();
        c = c.rotate_elements_right::<2>();
        d = d.rotate_elements_right::<3>();

        [a, b, c, d]
    }

    /// Transforms the state by performing the ChaCha block function.
    #[inline(always)]
    fn chacha_block(&mut self) {
        let mut working_state = self.matrix;

        for _ in 0..10 {
            working_state = Self::double_round(working_state);
        }

        // Add the working state to the original state.
        (0..4).for_each(|i| {
            self.matrix[i] = working_state[i].wrapping_add(self.matrix[i]);
        });
    }

    /// Expose the 512-bit state as a byte stream.
    #[inline(always)]
    fn keystream(&self) -> [u8; 64] {
        let mut keystream = [0u8; 64];
        for i in 0..4 {
            keystream[i * 16..(i + 1) * 16].copy_from_slice(&self.matrix[i].to_le_bytes());
        }
        keystream
    }
}

/// The ChaCha20 stream cipher from RFC8439.
///
/// The 20-round IETF version uses a 96-bit nonce and 32-bit block counter. This is the
/// variant used in the Bitcoin ecosystem, including BIP-0324.
pub struct ChaCha20 {
    /// Secret key shared by the parties communicating.
    key: Key,
    /// A key and nonce pair should only be used once.
    nonce: Nonce,
    /// Internal block index of keystream.
    block_count: u32,
    /// Internal byte offset index of the block_count.
    seek_offset_bytes: usize,
}

impl ChaCha20 {
    /// Make a new instance of ChaCha20 from an index in the keystream.
    pub const fn new(key: Key, nonce: Nonce, seek: u32) -> Self {
        let block_count = seek / 64;
        let seek_offset_bytes = (seek % 64) as usize;
        ChaCha20 { key, nonce, block_count, seek_offset_bytes }
    }

    /// Make a new instance of ChaCha20 from a block in the keystream.
    pub const fn new_from_block(key: Key, nonce: Nonce, block: u32) -> Self {
        ChaCha20 { key, nonce, block_count: block, seek_offset_bytes: 0 }
    }

    /// Gets the keystream for a specific block.
    #[inline(always)]
    fn keystream_at_block(&self, block: u32) -> [u8; 64] {
        let mut state = State::new(self.key, self.nonce, block);
        state.chacha_block();
        state.keystream()
    }

    /// Apply the keystream to a buffer updating the cipher block state as necessary.
    pub fn apply_keystream(&mut self, buffer: &mut [u8]) {
        // If we have an initial offset, handle the first partial block to get back to alignment.
        let remaining_buffer = if self.seek_offset_bytes != 0 {
            let bytes_until_aligned = 64 - self.seek_offset_bytes;
            let bytes_to_process = buffer.len().min(bytes_until_aligned);

            let keystream = self.keystream_at_block(self.block_count);
            for (buffer_byte, keystream_byte) in
                buffer[..bytes_to_process].iter_mut().zip(&keystream[self.seek_offset_bytes..])
            {
                *buffer_byte ^= *keystream_byte;
            }

            if bytes_to_process < bytes_until_aligned {
                self.seek_offset_bytes += bytes_to_process;
                return;
            }

            self.block_count += 1;
            self.seek_offset_bytes = 0;
            &mut buffer[bytes_to_process..]
        } else {
            buffer
        };

        // Process full blocks.
        let mut chunks = remaining_buffer.chunks_exact_mut(CHACHA_BLOCKSIZE);
        for chunk in &mut chunks {
            let keystream = self.keystream_at_block(self.block_count);
            for (buffer_byte, keystream_byte) in chunk.iter_mut().zip(keystream.iter()) {
                *buffer_byte ^= *keystream_byte;
            }
            self.block_count += 1;
        }

        // Handle any remaining bytes as partial block.
        let remainder = chunks.into_remainder();
        if !remainder.is_empty() {
            let keystream = self.keystream_at_block(self.block_count);
            for (buffer_byte, keystream_byte) in remainder.iter_mut().zip(keystream.iter()) {
                *buffer_byte ^= *keystream_byte;
            }
            self.seek_offset_bytes = remainder.len();
        }
    }

    /// Gets the keystream for specified block.
    pub fn get_keystream(&self, block: u32) -> [u8; 64] { self.keystream_at_block(block) }

    /// Updates the index of the keystream to the given byte.
    pub fn seek(&mut self, seek: u32) {
        self.block_count = seek / 64;
        self.seek_offset_bytes = (seek % 64) as usize;
    }

    /// Updates the index of the keystream to a block.
    pub fn block(&mut self, block: u32) {
        self.block_count = block;
        self.seek_offset_bytes = 0;
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use alloc::vec::Vec;

    use hex::prelude::*;

    use super::*;

    #[test]
    fn chacha_block() {
        let mut state = State {
            matrix: [
                U32x4([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]),
                U32x4([0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c]),
                U32x4([0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c]),
                U32x4([0x00000001, 0x09000000, 0x4a000000, 0x00000000]),
            ],
        };
        state.chacha_block();

        let expected = [
            U32x4([0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3]),
            U32x4([0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3]),
            U32x4([0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9]),
            U32x4([0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2]),
        ];

        for (actual, expected) in state.matrix.iter().zip(expected.iter()) {
            assert_eq!(actual.0, expected.0);
        }
    }

    #[test]
    fn prepare_state() {
        let key =
            Key(Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap());
        let nonce = Nonce(Vec::from_hex("000000090000004a00000000").unwrap().try_into().unwrap());
        let count = 1;
        let state = State::new(key, nonce, count);
        assert_eq!(state.matrix[1].0[0].to_be_bytes().to_lower_hex_string(), "03020100");
        assert_eq!(state.matrix[2].0[2].to_be_bytes().to_lower_hex_string(), "1b1a1918");
        assert_eq!(state.matrix[3].0[2].to_be_bytes().to_lower_hex_string(), "4a000000");
        assert_eq!(state.matrix[3].0[3].to_be_bytes().to_lower_hex_string(), "00000000");
        assert_eq!(state.matrix[3].0[0].to_be_bytes().to_lower_hex_string(), "00000001");
    }

    #[test]
    fn small_plaintext() {
        let key =
            Key(Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap());
        let nonce = Nonce(Vec::from_hex("000000090000004a00000000").unwrap().try_into().unwrap());
        let count = 1;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = [8; 3];
        chacha.apply_keystream(&mut binding[..]);
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!([8; 3], binding);
    }

    #[test]
    fn modulo_64() {
        let key =
            Key(Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap());
        let nonce = Nonce(Vec::from_hex("000000090000004a00000000").unwrap().try_into().unwrap());
        let count = 1;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = [8; 64];
        chacha.apply_keystream(&mut binding[..]);
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!([8; 64], binding);
    }

    #[test]
    fn rfc_standard() {
        let key =
            Key(Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap());
        let nonce = Nonce(Vec::from_hex("000000000000004a00000000").unwrap().try_into().unwrap());
        let count = 64;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let to = binding;
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding[..], Vec::from_hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d").unwrap());
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        let binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        assert_eq!(binding, to);
    }

    #[test]
    fn new_from_block() {
        let key =
            Key(Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap());
        let nonce = Nonce(Vec::from_hex("000000000000004a00000000").unwrap().try_into().unwrap());
        let block: u32 = 1;
        let mut chacha = ChaCha20::new_from_block(key, nonce, block);
        let mut binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let to = binding;
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding[..], Vec::from_hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d").unwrap());
        chacha.block(block);
        chacha.apply_keystream(&mut binding[..]);
        let binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        assert_eq!(binding, to);
    }

    #[test]
    fn multiple_partial_applies() {
        let key =
            Key(Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap());
        let nonce = Nonce(Vec::from_hex("000000000000004a00000000").unwrap().try_into().unwrap());

        // Create two instances, one for a full single pass and one for chunked partial calls.
        let mut chacha_full = ChaCha20::new(key, nonce, 0);
        let mut chacha_chunked = ChaCha20::new(key, nonce, 0);

        // Test data that crosses block boundaries.
        let mut full_buffer = [0u8; 100];
        let mut chunked_buffer = [0u8; 100];
        for (i, byte) in full_buffer.iter_mut().enumerate() {
            *byte = i as u8;
        }
        chunked_buffer.copy_from_slice(&full_buffer);

        // Apply keystream to full buffer.
        chacha_full.apply_keystream(&mut full_buffer);
        // Apply keystream in multiple calls to chunked buffer.
        chacha_chunked.apply_keystream(&mut chunked_buffer[..30]); // Partial block
        chacha_chunked.apply_keystream(&mut chunked_buffer[30..82]); // Cross block boundary
        chacha_chunked.apply_keystream(&mut chunked_buffer[82..]); // End with partial block

        assert_eq!(full_buffer, chunked_buffer);
    }
}
