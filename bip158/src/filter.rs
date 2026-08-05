// SPDX-License-Identifier: CC0-1.0

//! BIP-0158 basic compact block filters.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cmp::Ordering;

use encoding::{
    decode_from_slice_unbounded_with_decoder, CompactSizeEncoder, CompactSizeU64Decoder, Encoder,
};
use hashes::{sha256d, siphash24};
use internals::array::ArrayExt;
use primitives::{Block, BlockChecked, BlockHash, OutPoint, ScriptPubKey};

pub use self::error::{BuildError, DecodeError};
use crate::FilterHash;

/// The BIP-0157 type identifier for a BIP-0158 basic filter.
pub const BASIC_FILTER_TYPE: u8 = 0;
/// The Golomb-Rice remainder bit count used by basic filters.
pub const BASIC_FILTER_P: u8 = 19;
/// The inverse false-positive rate used by basic filters.
pub const BASIC_FILTER_M: u32 = 784_931;

/// A validated, canonically constructible BIP-0158 basic block filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicFilter {
    bytes: Vec<u8>,
    element_count: u32,
    payload_offset: u8,
}

impl BasicFilter {
    /// Constructs a basic filter for `block`.
    ///
    /// `prevout_script` must return the scriptPubKey spent by each non-coinbase input. It may return
    /// either owned or borrowed scripts.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::Prevout`] if a previous output cannot be resolved, or
    /// [`BuildError::TooManyElements`] if the block produces 2^32 or more distinct elements.
    pub fn from_block<F, S, E>(
        block: &Block<BlockChecked>,
        mut prevout_script: F,
    ) -> Result<Self, BuildError<E>>
    where
        F: FnMut(&OutPoint) -> Result<S, E>,
        S: AsRef<ScriptPubKey>,
    {
        let mut elements = BTreeSet::<Vec<u8>>::new();

        for transaction in block.transactions() {
            for output in &transaction.outputs {
                let script = &output.script_pubkey;
                if !script.is_empty() && !script.is_op_return() {
                    elements.insert(script.to_vec());
                }
            }
        }

        for outpoint in
            block.transactions().iter().skip(1).flat_map(|transaction| {
                transaction.inputs.iter().map(|input| &input.previous_output)
            })
        {
            let script = prevout_script(outpoint).map_err(BuildError::Prevout)?;
            let script = script.as_ref();
            if !script.is_empty() {
                elements.insert(script.to_vec());
            }
        }

        if elements.len() > u32::MAX as usize {
            return Err(BuildError::TooManyElements);
        }
        Ok(Self::from_elements(block.block_hash(), &elements))
    }

    /// Parses and validates serialized BIP-0158 basic-filter bytes.
    ///
    /// Unused bits in the final byte are ignored for compatibility with Bitcoin Core. Extra full
    /// bytes, noncanonical `CompactSize` values, truncated filters, and arithmetic overflow are
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not a structurally valid basic filter.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, DecodeError> {
        let (element_count, payload_offset) = validate(&bytes)?;
        Ok(Self { bytes, element_count, payload_offset })
    }

    /// Returns whether any query element matches this filter.
    ///
    /// An empty query returns `false`.
    pub fn match_any<I, T>(&self, blockhash: BlockHash, query: I) -> bool
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut query = query.into_iter().peekable();
        let element_count = u64::from(self.element_count);
        if element_count == 0 || query.peek().is_none() {
            return false;
        }

        let range = element_count * u64::from(BASIC_FILTER_M);
        let key = SipHashKey::from_block_hash(blockhash);
        let mut queries = query
            .map(|element| map_to_range(key.hash(element.as_ref()), range))
            .collect::<Vec<_>>();
        queries.sort_unstable();

        match_sorted(self.payload(), element_count, &queries, false).unwrap_or(false)
    }

    /// Returns whether every query element matches this filter.
    ///
    /// An empty query returns `true`.
    pub fn match_all<I, T>(&self, blockhash: BlockHash, query: I) -> bool
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut query = query.into_iter().peekable();
        if query.peek().is_none() {
            return true;
        }
        let element_count = u64::from(self.element_count);
        if element_count == 0 {
            return false;
        }

        let range = element_count * u64::from(BASIC_FILTER_M);
        let key = SipHashKey::from_block_hash(blockhash);
        let mut queries = query
            .map(|element| map_to_range(key.hash(element.as_ref()), range))
            .collect::<Vec<_>>();
        queries.sort_unstable();
        queries.dedup();

        match_sorted(self.payload(), element_count, &queries, true).unwrap_or(false)
    }

    /// Computes the canonical double-SHA256 filter hash.
    pub fn filter_hash(&self) -> FilterHash {
        FilterHash::from_byte_array(sha256d::Hash::hash(&self.bytes).to_byte_array())
    }

    /// Returns the serialized filter.
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }

    /// Unwraps the filter into its serialized representation.
    pub fn into_bytes(self) -> Vec<u8> { self.bytes }

    fn payload(&self) -> &[u8] { &self.bytes[usize::from(self.payload_offset)..] }

    fn from_elements(blockhash: BlockHash, elements: &BTreeSet<Vec<u8>>) -> Self {
        let count = elements.len();
        let range = count as u64 * u64::from(BASIC_FILTER_M);
        let key = SipHashKey::from_block_hash(blockhash);
        let mut mapped = elements
            .iter()
            .map(|element| map_to_range(key.hash(element), range))
            .collect::<Vec<_>>();
        mapped.sort_unstable();

        let count_encoder = CompactSizeEncoder::new(count);
        let mut bytes = Vec::with_capacity(
            count_encoder.current_chunk().len().saturating_add(count.saturating_mul(3)),
        );
        bytes.extend_from_slice(count_encoder.current_chunk());

        let mut bit_writer = BitWriter::new(bytes);
        let mut previous = 0;
        for value in mapped {
            bit_writer.write_golomb_rice(value - previous);
            previous = value;
        }
        Self {
            bytes: bit_writer.finish(),
            element_count: count as u32,
            payload_offset: count_encoder.current_chunk().len() as u8,
        }
    }
}

impl TryFrom<Vec<u8>> for BasicFilter {
    type Error = DecodeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> { Self::from_bytes(bytes) }
}

impl AsRef<[u8]> for BasicFilter {
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

fn map_to_range(hash: u64, range: u64) -> u64 {
    ((u128::from(hash) * u128::from(range)) >> 64) as u64
}

fn decode_count(bytes: &[u8]) -> Result<(u64, &[u8]), DecodeError> {
    let mut remaining = bytes;
    let count = decode_from_slice_unbounded_with_decoder::<CompactSizeU64Decoder>(&mut remaining)
        .map_err(DecodeError::InvalidElementCount)?;
    if count > u64::from(u32::MAX) {
        return Err(DecodeError::ElementCountTooLarge(count));
    }
    Ok((count, remaining))
}

fn validate(bytes: &[u8]) -> Result<(u32, u8), DecodeError> {
    let (count, payload) = decode_count(bytes)?;
    let minimum_bits =
        count.checked_mul(u64::from(BASIC_FILTER_P) + 1).ok_or(DecodeError::ValueOverflow)?;
    let available_bits = u64::try_from(payload.len()).unwrap_or(u64::MAX).saturating_mul(8);
    if minimum_bits > available_bits {
        return Err(DecodeError::FilterTooShort);
    }

    let mut reader = BitReader::new(payload);
    let mut value = 0u64;
    for _ in 0..count {
        let delta = reader.read_golomb_rice()?;
        value = value.checked_add(delta).ok_or(DecodeError::ValueOverflow)?;
    }
    if reader.consumed_bytes() != payload.len() {
        return Err(DecodeError::TrailingData);
    }
    let payload_offset = bytes.len() - payload.len();
    Ok((count as u32, payload_offset as u8))
}

fn match_sorted(
    payload: &[u8],
    element_count: u64,
    queries: &[u64],
    require_all: bool,
) -> Result<bool, DecodeError> {
    let mut reader = BitReader::new(payload);
    let mut value = 0u64;
    let mut query_index = 0usize;

    for _ in 0..element_count {
        value = value.checked_add(reader.read_golomb_rice()?).ok_or(DecodeError::ValueOverflow)?;

        while query_index < queries.len() {
            match queries[query_index].cmp(&value) {
                Ordering::Less if require_all => return Ok(false),
                Ordering::Less => query_index += 1,
                Ordering::Equal if !require_all => return Ok(true),
                Ordering::Equal => {
                    query_index += 1;
                    break;
                }
                Ordering::Greater => break,
            }
        }
        if query_index == queries.len() {
            return Ok(require_all);
        }
    }
    Ok(false)
}

#[derive(Copy, Clone)]
struct SipHashKey {
    first: u64,
    second: u64,
}

impl SipHashKey {
    fn from_block_hash(blockhash: BlockHash) -> Self {
        let bytes = blockhash.to_byte_array();
        let first = u64::from_le_bytes(*bytes.sub_array::<0, 8>());
        let second = u64::from_le_bytes(*bytes.sub_array::<8, 8>());
        Self { first, second }
    }

    fn hash(self, element: &[u8]) -> u64 {
        siphash24::Hash::hash_to_u64_with_keys(self.first, self.second, element)
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bit_position: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, bit_position: 0 } }

    fn read_bit(&mut self) -> Result<u8, DecodeError> {
        let byte = self.bytes.get(self.bit_position / 8).ok_or(DecodeError::FilterTooShort)?;
        let bit = (byte >> (7 - self.bit_position % 8)) & 1;
        self.bit_position += 1;
        Ok(bit)
    }

    fn read_bits(&mut self, count: u8) -> Result<u64, DecodeError> {
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | u64::from(self.read_bit()?);
        }
        Ok(value)
    }

    fn read_golomb_rice(&mut self) -> Result<u64, DecodeError> {
        let mut quotient: u64 = 0;
        while self.read_bit()? == 1 {
            quotient = quotient.checked_add(1).ok_or(DecodeError::ValueOverflow)?;
        }
        if quotient > (u64::MAX >> BASIC_FILTER_P) {
            return Err(DecodeError::ValueOverflow);
        }
        Ok((quotient << BASIC_FILTER_P) | self.read_bits(BASIC_FILTER_P)?)
    }

    fn consumed_bytes(&self) -> usize { self.bit_position.saturating_add(7) / 8 }
}

struct BitWriter {
    bytes: Vec<u8>,
    bit_offset: u8,
}

impl BitWriter {
    fn new(bytes: Vec<u8>) -> Self { Self { bytes, bit_offset: 0 } }

    fn write_bit(&mut self, bit: bool) {
        if self.bit_offset == 0 {
            self.bytes.push(0);
        }
        if bit {
            let last = self.bytes.last_mut().expect("byte was just pushed");
            *last |= 1 << (7 - self.bit_offset);
        }
        self.bit_offset = (self.bit_offset + 1) % 8;
    }

    fn write_bits(&mut self, value: u64, count: u8) {
        for shift in (0..count).rev() {
            self.write_bit(((value >> shift) & 1) != 0);
        }
    }

    fn write_golomb_rice(&mut self, value: u64) {
        for _ in 0..(value >> BASIC_FILTER_P) {
            self.write_bit(true);
        }
        self.write_bit(false);
        self.write_bits(value, BASIC_FILTER_P);
    }

    fn finish(self) -> Vec<u8> { self.bytes }
}

pub mod error {
    use core::fmt;
    #[cfg(feature = "std")]
    use std::error::Error;

    /// An error constructing a BIP-0158 filter from a block.
    #[derive(Debug)]
    pub enum BuildError<E> {
        /// Looking up a previous output script failed.
        Prevout(E),
        /// BIP-0158 requires the number of elements to be less than 2^32.
        TooManyElements,
    }

    impl<E: fmt::Display> fmt::Display for BuildError<E> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Prevout(e) => write!(f, "failed to resolve previous output: {}", e),
                Self::TooManyElements => f.write_str("filter data contains 2^32 or more elements"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl<E> Error for BuildError<E>
    where
        E: Error + 'static,
    {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::Prevout(e) => Some(e),
                Self::TooManyElements => None,
            }
        }
    }

    /// An error decoding a BIP-0158 filter.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum DecodeError {
        /// The filter's element count is not canonical `CompactSize`.
        InvalidElementCount(encoding::CompactSizeDecoderError),
        /// BIP-0158 requires the number of elements to be less than 2^32.
        ElementCountTooLarge(u64),
        /// The encoded filter is too short for its claimed number of elements.
        FilterTooShort,
        /// A Golomb-Rice value cannot be represented by a u64.
        ValueOverflow,
        /// Bytes remain after decoding the claimed number of elements.
        TrailingData,
    }

    impl fmt::Display for DecodeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidElementCount(e) => write!(f, "invalid filter element count: {}", e),
                Self::ElementCountTooLarge(count) => {
                    write!(f, "filter element count {} is not less than 2^32", count)
                }
                Self::FilterTooShort =>
                    f.write_str("filter is shorter than its element count requires"),
                Self::ValueOverflow => f.write_str("Golomb-Rice value overflows u64"),
                Self::TrailingData => f.write_str("filter contains trailing data"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl Error for DecodeError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::InvalidElementCount(e) => Some(e),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn empty_filter() {
        let filter = BasicFilter::from_bytes(vec![0]).unwrap();
        let block_hash = BlockHash::from_byte_array([0; 32]);
        assert_eq!(filter.as_bytes(), &[0]);
        assert!(!filter.match_any(block_hash, [b"anything"]));
        assert!(filter.match_all(block_hash, core::iter::empty::<&[u8]>()));
        assert!(!filter.match_all(block_hash, [b"anything"]));
    }

    #[test]
    fn malformed_filters_are_rejected() {
        assert!(matches!(
            BasicFilter::from_bytes(vec![]),
            Err(DecodeError::InvalidElementCount(_))
        ));
        assert!(matches!(
            BasicFilter::from_bytes(vec![0xfd, 0xfc, 0x00]),
            Err(DecodeError::InvalidElementCount(_))
        ));
        assert!(matches!(BasicFilter::from_bytes(vec![1]), Err(DecodeError::FilterTooShort)));
        assert!(matches!(BasicFilter::from_bytes(vec![0, 0]), Err(DecodeError::TrailingData)));
    }

    #[test]
    fn accepts_decoded_values_outside_construction_range() {
        // BIP-0158 constrains constructed values to [0, N*M), but, like Bitcoin Core, decoding is
        // structural and accepts values at or above that construction range.
        BasicFilter::from_bytes(vec![1, 0x9f, 0xd1, 0x18]).unwrap(); // N*M
        BasicFilter::from_bytes(vec![1, 0x9f, 0xd1, 0x20]).unwrap(); // N*M + 1
    }

    #[test]
    fn oversized_element_count_is_rejected() {
        let bytes = vec![0xff, 0, 0, 0, 0, 1, 0, 0, 0];
        assert!(matches!(
            BasicFilter::from_bytes(bytes),
            Err(DecodeError::ElementCountTooLarge(0x1_0000_0000))
        ));
    }

    #[test]
    fn nonzero_padding_is_accepted() {
        let mut elements = BTreeSet::new();
        elements.insert(b"element".to_vec());
        let block_hash = BlockHash::from_byte_array([42; 32]);
        let filter = BasicFilter::from_elements(block_hash, &elements);
        let mut bytes = filter.into_bytes();
        *bytes.last_mut().unwrap() |= 1;
        BasicFilter::from_bytes(bytes).unwrap();
    }

    #[test]
    fn round_trip_and_query() {
        let mut elements = BTreeSet::new();
        elements.insert(b"first".to_vec());
        elements.insert(b"second".to_vec());
        elements.insert(b"third".to_vec());
        let block_hash = BlockHash::from_byte_array([7; 32]);
        let filter = BasicFilter::from_elements(block_hash, &elements);
        let reparsed = BasicFilter::from_bytes(filter.clone().into_bytes()).unwrap();

        assert_eq!(filter, reparsed);
        assert!(filter.match_any(block_hash, [b"missing".as_slice(), b"second".as_slice()]));
        assert!(filter.match_all(block_hash, [b"first".as_slice(), b"third".as_slice()]));
        assert!(!filter.match_all(block_hash, [b"first".as_slice(), b"missing".as_slice()]));
    }
}
