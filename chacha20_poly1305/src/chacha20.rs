// SPDX-License-Identifier: CC0-1.0

//! The `ChaCha20` stream cipher from RFC8439.

use core::ops::BitXor;

/// The first four words (32-bit) of the `ChaCha` stream cipher state are constants.
const WORD_1: u32 = 0x6170_7865;
const WORD_2: u32 = 0x3320_646e;
const WORD_3: u32 = 0x7962_2d32;
const WORD_4: u32 = 0x6b20_6574;

/// The cipher's block size is 64 bytes.
const CHACHA_BLOCKSIZE: usize = 64;

/// A 256-bit secret key shared by the parties communicating.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(pub(super) [u8; 32]);

impl Key {
    /// Constructs a new key.
    pub const fn new(key: [u8; 32]) -> Self { Self(key) }
}

/// A 96-bit initialization vector (IV), or nonce.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Constructs a new nonce.
    pub const fn new(nonce: [u8; 12]) -> Self { Self(nonce) }
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct U32x4([u32; 4]);

impl U32x4 {
    #[inline(always)]
    fn wrapping_add(self, rhs: Self) -> Self {
        let mut result = [0u32; 4];
        (0..4).for_each(|i| {
            result[i] = self.0[i].wrapping_add(rhs.0[i]);
        });
        Self(result)
    }

    #[inline(always)]
    fn rotate_left(self, n: u32) -> Self {
        let mut result = [0u32; 4];
        (0..4).for_each(|i| {
            result[i] = self.0[i].rotate_left(n);
        });
        Self(result)
    }

    #[inline(always)]
    fn rotate_elements_left<const N: u32>(self) -> Self
    where
        (): UpTo3<N>,
    {
        match N {
            1 => Self([self.0[1], self.0[2], self.0[3], self.0[0]]),
            2 => Self([self.0[2], self.0[3], self.0[0], self.0[1]]),
            3 => Self([self.0[3], self.0[0], self.0[1], self.0[2]]),
            _ => self, // Rotate by 0 is a no-op.
        }
    }

    #[inline(always)]
    fn rotate_elements_right<const N: u32>(self) -> Self
    where
        (): UpTo3<N>,
    {
        match N {
            1 => Self([self.0[3], self.0[0], self.0[1], self.0[2]]),
            2 => Self([self.0[2], self.0[3], self.0[0], self.0[1]]),
            3 => Self([self.0[1], self.0[2], self.0[3], self.0[0]]),
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
        Self(result)
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

        Self {
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
    /// The underlying `quarter_round` function is vectorized using the
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

    /// Transforms the state by performing the `ChaCha` block function.
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

/// The `ChaCha20` stream cipher from RFC8439.
///
/// The 20-round IETF version uses a 96-bit nonce and 32-bit block counter. This is the
/// variant used in the Bitcoin ecosystem, including BIP-0324.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChaCha20 {
    /// Secret key shared by the parties communicating.
    key: Key,
    /// A key and nonce pair should only be used once.
    nonce: Nonce,
    /// Internal block index of keystream.
    block_count: u32,
    /// Internal byte offset index of the `block_count`.
    seek_offset_bytes: usize,
}

impl ChaCha20 {
    /// Make a new instance of `ChaCha20` from an index in the keystream.
    pub const fn new(key: Key, nonce: Nonce, seek: u32) -> Self {
        let block_count = seek / 64;
        let seek_offset_bytes = (seek % 64) as usize;
        Self { key, nonce, block_count, seek_offset_bytes }
    }

    /// Make a new instance of `ChaCha20` from a block in the keystream.
    pub const fn new_from_block(key: Key, nonce: Nonce, block: u32) -> Self {
        Self { key, nonce, block_count: block, seek_offset_bytes: 0 }
    }

    /// Gets the keystream for a specific block.
    #[cfg(not(chacha20_poly1305_fuzz))]
    #[inline(always)]
    fn keystream_at_block(&self, block: u32) -> [u8; 64] {
        let mut state = State::new(self.key, self.nonce, block);
        state.chacha_block();
        state.keystream()
    }

    /// Gets the keystream for a specific block.
    #[cfg(chacha20_poly1305_fuzz)]
    fn keystream_at_block(&self, _block: u32) -> [u8; 64] { [0u8; 64] }

    /// Apply the keystream to a buffer updating the cipher block state as necessary.
    #[cfg(not(chacha20_poly1305_fuzz))]
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

    /// Apply the keystream to a buffer updating the cipher block state as necessary.
    #[cfg(chacha20_poly1305_fuzz)]
    pub fn apply_keystream(&mut self, _buffer: &mut [u8]) {}

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
    use hex::{hex, DisplayHex as _};

    use super::*;

    #[test]
    fn chacha_block() {
        let mut state = State {
            matrix: [
                U32x4([0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]),
                U32x4([0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c]),
                U32x4([0x1312_1110, 0x1716_1514, 0x1b1a_1918, 0x1f1e_1d1c]),
                U32x4([0x0000_0001, 0x0900_0000, 0x4a00_0000, 0x0000_0000]),
            ],
        };
        state.chacha_block();

        let expected = [
            U32x4([0xe4e7_f110, 0x1559_3bd1, 0x1fdd_0f50, 0xc471_20a3]),
            U32x4([0xc7f4_d1c7, 0x0368_c033, 0x9aaa_2204, 0x4e6c_d4c3]),
            U32x4([0x4664_82d2, 0x09aa_9f07, 0x05d7_c214, 0xa202_8bd9]),
            U32x4([0xd19c_12b5, 0xb94e_16de, 0xe883_d0cb, 0x4e3c_50a2]),
        ];

        for (actual, expected) in state.matrix.iter().zip(expected.iter()) {
            assert_eq!(actual.0, expected.0);
        }
    }

    #[test]
    fn prepare_state() {
        let key = Key(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce(hex!("000000090000004a00000000"));
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
        let key = Key(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce(hex!("000000090000004a00000000"));
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
        let key = Key(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce(hex!("000000090000004a00000000"));
        let count = 1;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = [8; 64];
        chacha.apply_keystream(&mut binding[..]);
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!([8; 64], binding);
    }

    #[cfg(not(chacha20_poly1305_fuzz))]
    #[test]
    fn rfc_standard() {
        let key = Key(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce(hex!("000000000000004a00000000"));
        let count = 64;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let to = binding;
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding[..], hex!("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"));
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        let binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        assert_eq!(binding, to);
    }

    #[cfg(not(chacha20_poly1305_fuzz))]
    #[test]
    fn rfc_appendix_a2() {
        let key = Key(hex!("0000000000000000000000000000000000000000000000000000000000000001"));
        let nonce = Nonce(hex!("000000000000000000000002"));
        let count = 64;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = *b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
        let to = binding;
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding[..], hex!("a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"));
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        let binding = *b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
        assert_eq!(binding, to);
    }

    // Test vector covering more than 8 blocks, such that both 4 and 8 block processing are tested.
    //
    // https://github.com/torvalds/linux/blob/238650ef6c7c7cca08e032527329424c9fbd70e5/crypto/testmgr.h#L28447
    #[cfg(not(chacha20_poly1305_fuzz))]
    #[test]
    fn linux_kernel_long_data() {
        let key = Key(hex!("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"));
        let nonce = Nonce(hex!("000000000000000000000001"));
        let count = 1792;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = hex!("49eee0dc249040cdc5408f4705bcdd8147c68de6b18fd7cb090e6e22481fbfb85cf71e8ac123f2d4194b010f4ea443ce01c667da03911890a5a48e4503b32dac7492d35347c8dd25536c0203870d110c58e31218fd2a5b400c30f0b83f43ceae653a7d7cf454aacc3397c377bac570ded7d513a565c45f0f461a0d97b5f3bb3c840f2bc5aaeaf26cc9b50cee15f37dbe9f7b5aa6ae4f83b6794941f45818cb867f300ef87d4436ea75eb8884403cad4f6f316baa5de5a5c52166e9a7e3b2158878f679a15947124e9f9f641aa0225b08be7c36c22b66331bdd6071f7478c61c3da8a781e16fa1e8681a6172aa7b5c2e7a4c742f1cf6acab445cff393f0e7eaf6f4e633438493a5679b165858800f2b5c2474757f9581b7307a33a7f794873227105d144c4329dd26bd3e3c0efe0ea510ea6b64fd73c6edeca8c9bfb3ba0b4d0770fc16fd791ed7c5494e1c8b8d791bb1ecca60094c6ad50949460088228dceeab11711de42d223c17211f55073044047f95de7a726b17eb03f58c152ab12679d3f434b68d49c6838078a2d3ef3af6a4bf9e5316922f9a669c69c969a1235951d95d5ddbebf935324fdebc20a64b077006f88c43718697cd74192554c03a19a4b15e5df7f373372c18b1067a3015794257b38717edd1ecc7355d28eeb07ddf1da58b14790fe422172a3547aa040ec9fddc6846ecaaee368b49de478ff57f2f81b03a131d9de8df5229cdd20a41e27b1764f4455e29ba19cfe54f7271bf4de02f51b55485cdc214b9e4b6eed4623dc65b2cf795f28e09e8be74c9d8affc1a628b865698a4529ef7485de79c708ae30b0f4a31d5141abcecbf6b5d86de085e198b343bb86830aa0f5b7040bfa711fb0f6d9130015f0c7eb0d5a9fd7b96c651422456e45323e7e601a12978214fbaa0422faa0e57e8c7802485d78335a7caddb29cebb8b61a4b742e2ac8b1ad92f0b8b622183357ead73c2b56c10263807e5c73680e2231261f5484b2bc5df15d98701aaac1e7cad73781863e08b9f81d8126a2810be04688a097c1b1c8366804780e8fd351c976fae491066ccc6d8cc3a8491207772e424d2379fc5c92594105f40006499dcaed72109785015ac5fc62ca20ba939876e6dabde085116c713e9eaed068e2cf8378cf0a6968d43b69837b243eddedf891ae7eb9da17b0b77b0e275c0f198d98055c93491d159e84b0fc1a94b7a840620a85dfad1de70562f9e919c20b324d8843de18c7e6252e5444b9fc29303ea2b59c5fa3f912bbb23f5b27bf538afb3ee63dc7bd1ffaa8bab826b3704eb74be79b98390ef205946ffe9973e2feeb66418384c7a4af961e89aa1b501a647d311d4ced3914988c7b84db1b9076d1672ae465e03a14bb60230a83da9072a7c19e76287e3822f6fe109d99497eadd589eae767e35e5b4da7ef4def73287cd93bf115611be0874e169ade2d7f886758a3ca4be70a71bfc0b442a7635ea5d8581af85eba01c61c2f74fa5dc027ff695406e8a9af35d256e143a22c9371ceb46543fa591c2b58cfe530897321bb23027fe255ddc0887d0e5941ad4f1fed6b4a3e674813c1bb731a722fdd4dd204e7c51b06073b89cac91907e01b0e18a2f751c532a982a06529552b2e9252e4ce25a00b213810377660da599da4e8cacf313532745af6446dcea23da97d1ab7d6c30961fbc0634180b5e2135118d4ce02de950167481a8b434b97242a6ccbcca348327105b68458f52220c553d297ce3c0660542915f58fe4a62d98ca9041904a9084b57fc6753087cbc668ab0b69f92d6417c5b2a007972");
        let to = binding;
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding, hex!("45e8e0b69ccafd87e81d37968ae34035cf5e3a463dfbd069deaf7ad50de952ecc282e53e7db24ad9bbc39fc05dac938d0e6fd3d7fb6a0dce922cf7bb9357ccee42726fc84bd276bfa0e37a39f95c8efda11d41e508c11c1192fd395c51d02f66334a7115feee12548c8f34d8503c18a6c5e1468afb5f7e259be2c366412bb3a5570e94172639bb54ae2e6f42fb4d896f9df1162ee3e7fce3b24b2ba67c04693a705aa7f1316419ca4579d8582361afc25205c30bc1647c81d911cfff023d518401acc62e342b093aa85d980e89d9ef8fd9d77ddd6347467da1da0b537d79cdc986dd6b13a19a70dd5ca1693ce45de38ce5f4879c10cf0f0bc843dcf81d625e5be20306c571b648a5f00f2dd5a273558f01a759805f116c40ffb1f2c67e01bb1c699cc93f715f077edf6f99ca9cfdf9b949e7cc91d59b8f03aee76132ef416c75849b8cce1d6b932141ecc6ad8e0c48a8e2f557def738fd4a6fa74af9ac7db1857d6c950a5acf68d2e07a26d9c16d3ec637bdbe2436779f1bc122f379ae9578669711c01af1e80d3809c2eeb7d3467b597723e8b4923d78bee22563a52a0670923263f9192168e10b9ad0ee21db1fe0de3e64024d0ee00aa9ed198ca8bfe32e75242bb0e5826a1e6f712a3a60ed060d17a2db291daeb2c4fb9404d858fcc4044eeec7c10fe99b632d023e0267e5d8bb79dfd2eb50e90a0246df68cfe72b0a56d6f7bc44adb8b55febbc746be87eb060c60d9609bb19bae03cc46cbf0f58c0556223a0ffb51cfd18e1cf6dd352b4cea6faaafb1b0b426d794248705b0edd3ac9698b7367f695db8cfbfdb5084742849afacc67b23cb6fdd832d604b64aea534bf59416adf0102e2db48babe589c73912f38db5960b875da77cb0c2f62e57972cdc541c3472de0c68399d32a575921332ea9027bd5b1db921021cccba975e4958e8ac8bf3ce3cf000e96caee977dff402cd5525899e90f36b8fb7d64798262f312f8dbf54cd99eb80d7acc308c2a632f124767c4f785355fb008ad652532545fb0a6bb9be3c5e11cc6addfca7c4794dbdfbce3af17adaebfe64283d0fee80ba0cf8e95b3ad4aec9f30ee85dc55c0b2020ee400dde07a714b490b6bd3bae7d2ba7c7dc0b4c5d65b0d2c5796123e0a2997355adc6fbc754b5981f8c86c23fbe5eea64a360189f80af52741afe22c29267400208ee675b67e03dde7aaf8e28f35e0ef44856aa8522d836ed3b3d686930bc7123b16e6103894403f432aa4c409f69fb7091cc1f11bd7667e6108b293968ea4e6daefb40cfe2d00d8d6fed9b8d647a948e323878eb7d5ff94d13be21ea16e75ceecdf65fc645b28f2bb5933e45dbfda26aec8392998747e07ca27bc42acdc0810398b087b6861364334cd799bfdb7b6eaa76cca0741ba36e83d4ba7a849d9171cd602d56fd2635cbebace9eea4fc185b91d5fe8445e0c7fd11e900b654dfe194de2b709f947f150e836310b3f5ead3e8d1a5fc1719689abc1730430a1a3392d42a2e6899bc49f068e3f01fcbccfabb055646848b698364c5e0c55299073ca65cafa3ded7db43e6b7764e4dd67160634a0c5fae258422905f26614d8fafc922f205cfc1dc68e5578e241b3059cad70dc3d3529e093e0eafdb5fc72bde3afdad93047406890e90eb85ffe63c1242f4fa80755e4ed72f930b3441028568d00312de92547a7efb55e788fba4a9f2d1c670063725eea76ed98986502e07dbfb2a86450e91f47cbb1260e83f71be8f9d26efd989c48fd8c573d884aa2fad221e7ecfa20823458942a030ebbfa1edadd576fa248f98"));
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding, to);
    }

    #[cfg(not(chacha20_poly1305_fuzz))]
    #[test]
    fn new_from_block() {
        let key = Key(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce(hex!("000000000000004a00000000"));
        let block: u32 = 1;
        let mut chacha = ChaCha20::new_from_block(key, nonce, block);
        let mut binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let to = binding;
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding[..], hex!("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"));
        chacha.block(block);
        chacha.apply_keystream(&mut binding[..]);
        let binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        assert_eq!(binding, to);
    }

    #[test]
    fn multiple_partial_applies() {
        let key = Key(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce(hex!("000000000000004a00000000"));

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
