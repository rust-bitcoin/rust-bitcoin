// Written in 2019 by Tammas Blummer.
// SPDX-License-Identifier: CC0-1.0

// This module was largely copied from https://github.com/rust-bitcoin/murmel/blob/master/src/blockfilter.rs
// on 11. June 2019 which is licensed under Apache, that file specifically
// was written entirely by Tamas Blummer, who is re-licensing its contents here as CC0.

//! BIP 158 Compact Block Filters for Light Clients.
//!
//! This module implements a structure for compact filters on block data, for
//! use in the BIP 157 light client protocol. The filter construction proposed
//! is an alternative to Bloom filters, as used in BIP 37, that minimizes filter
//! size by using Golomb-Rice coding for compression.
//!
//! ### Relevant BIPS
//!
//! * [BIP 157 - Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
//! * [BIP 158 - Compact Block Filters for Light Clients](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
//!
//! # Examples
//!
//! ```ignore
//! fn get_script_for_coin(coin: &OutPoint) -> Result<ScriptBuf, BlockFilterError> {
//!   // get utxo ...
//! }
//!
//! // create a block filter for a block (server side)
//! let filter = BlockFilter::new_script_filter(&block, get_script_for_coin)?;
//!
//! // or create a filter from known raw data
//! let filter = BlockFilter::new(content);
//!
//! // read and evaluate a filter
//!
//! let query: Iterator<Item=ScriptBuf> = // .. some scripts you care about
//! if filter.match_any(&block_hash, &mut query.map(|s| s.as_bytes())) {
//!   // get this block
//! }
//!  ```
//!

use core::cmp::{self, Ordering};
use core::convert::TryInto;
use core::fmt::{self, Display, Formatter};

use bitcoin_internals::write_err;

use crate::blockdata::block::Block;
use crate::blockdata::script::Script;
use crate::blockdata::transaction::OutPoint;
use crate::consensus::encode::VarInt;
use crate::consensus::{Decodable, Encodable};
use crate::hash_types::{BlockHash, FilterHash, FilterHeader};
use crate::hashes::{siphash24, Hash};
use crate::io;
use crate::prelude::*;

/// Golomb encoding parameter as in BIP-158, see also https://gist.github.com/sipa/576d5f09c3b86c3b1b75598d799fc845
const P: u8 = 19;
const M: u64 = 784931;

/// Errors for blockfilter.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Missing UTXO, cannot calculate script filter.
    UtxoMissing(OutPoint),
    /// IO error reading or writing binary serialization of the filter.
    Io(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::UtxoMissing(ref coin) => write!(f, "unresolved UTXO {}", coin),
            Error::Io(ref e) => write_err!(f, "IO error"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            UtxoMissing(_) => None,
            Io(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self { Error::Io(io) }
}

/// A block filter, as described by BIP 158.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFilter {
    /// Golomb encoded filter
    pub content: Vec<u8>,
}

impl FilterHash {
    /// Computes the filter header from a filter hash and previous filter header.
    pub fn filter_header(&self, previous_filter_header: &FilterHeader) -> FilterHeader {
        let mut header_data = [0u8; 64];
        header_data[0..32].copy_from_slice(&self[..]);
        header_data[32..64].copy_from_slice(&previous_filter_header[..]);
        FilterHeader::hash(&header_data)
    }
}

impl BlockFilter {
    /// Creates a new filter from pre-computed data.
    pub fn new(content: &[u8]) -> BlockFilter { BlockFilter { content: content.to_vec() } }

    /// Computes a SCRIPT_FILTER that contains spent and output scripts.
    pub fn new_script_filter<M, S>(block: &Block, script_for_coin: M) -> Result<BlockFilter, Error>
    where
        M: Fn(&OutPoint) -> Result<S, Error>,
        S: Borrow<Script>,
    {
        let mut out = Vec::new();
        let mut writer = BlockFilterWriter::new(&mut out, block);

        writer.add_output_scripts();
        writer.add_input_scripts(script_for_coin)?;
        writer.finish()?;

        Ok(BlockFilter { content: out })
    }

    /// Computes this filter's ID in a chain of filters (see [BIP 157]).
    ///
    /// [BIP 157]: <https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki#Filter_Headers>
    pub fn filter_header(&self, previous_filter_header: &FilterHeader) -> FilterHeader {
        let filter_hash = FilterHash::hash(self.content.as_slice());
        filter_hash.filter_header(previous_filter_header)
    }

    /// Returns true if any query matches against this [`BlockFilter`].
    pub fn match_any<I>(&self, block_hash: &BlockHash, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
    {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_any(&mut self.content.as_slice(), query)
    }

    /// Returns true if all queries match against this [`BlockFilter`].
    pub fn match_all<I>(&self, block_hash: &BlockHash, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
    {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_all(&mut self.content.as_slice(), query)
    }
}

/// Compiles and writes a block filter.
pub struct BlockFilterWriter<'a, W> {
    block: &'a Block,
    writer: GcsFilterWriter<'a, W>,
}

impl<'a, W: io::Write> BlockFilterWriter<'a, W> {
    /// Creates a new [`BlockFilterWriter`] from `block`.
    pub fn new(writer: &'a mut W, block: &'a Block) -> BlockFilterWriter<'a, W> {
        let block_hash_as_int = block.block_hash().to_byte_array();
        let k0 = u64::from_le_bytes(block_hash_as_int[0..8].try_into().expect("8 byte slice"));
        let k1 = u64::from_le_bytes(block_hash_as_int[8..16].try_into().expect("8 byte slice"));
        let writer = GcsFilterWriter::new(writer, k0, k1, M, P);
        BlockFilterWriter { block, writer }
    }

    /// Adds output scripts of the block to filter (excluding OP_RETURN scripts).
    pub fn add_output_scripts(&mut self) {
        for transaction in &self.block.txdata {
            for output in &transaction.output {
                if !output.script_pubkey.is_op_return() {
                    self.add_element(output.script_pubkey.as_bytes());
                }
            }
        }
    }

    /// Adds consumed output scripts of a block to filter.
    pub fn add_input_scripts<M, S>(&mut self, script_for_coin: M) -> Result<(), Error>
    where
        M: Fn(&OutPoint) -> Result<S, Error>,
        S: Borrow<Script>,
    {
        for script in self
            .block
            .txdata
            .iter()
            .skip(1) // skip coinbase
            .flat_map(|t| t.input.iter().map(|i| &i.previous_output))
            .map(script_for_coin)
        {
            match script {
                Ok(script) => self.add_element(script.borrow().as_bytes()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Adds an arbitrary element to filter.
    pub fn add_element(&mut self, data: &[u8]) { self.writer.add_element(data); }

    /// Writes the block filter.
    pub fn finish(&mut self) -> Result<usize, io::Error> { self.writer.finish() }
}

/// Reads and interprets a block filter.
pub struct BlockFilterReader {
    reader: GcsFilterReader,
}

impl BlockFilterReader {
    /// Creates a new [`BlockFilterReader`] from `block_hash`.
    pub fn new(block_hash: &BlockHash) -> BlockFilterReader {
        let block_hash_as_int = block_hash.to_byte_array();
        let k0 = u64::from_le_bytes(block_hash_as_int[0..8].try_into().expect("8 byte slice"));
        let k1 = u64::from_le_bytes(block_hash_as_int[8..16].try_into().expect("8 byte slice"));
        BlockFilterReader { reader: GcsFilterReader::new(k0, k1, M, P) }
    }

    /// Returns true if any query matches against this [`BlockFilterReader`].
    pub fn match_any<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: io::Read + ?Sized,
    {
        self.reader.match_any(reader, query)
    }

    /// Returns true if all queries match against this [`BlockFilterReader`].
    pub fn match_all<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: io::Read + ?Sized,
    {
        self.reader.match_all(reader, query)
    }
}

/// Golomb-Rice encoded filter reader.
pub struct GcsFilterReader {
    filter: GcsFilter,
    m: u64,
}

impl GcsFilterReader {
    /// Creates a new [`GcsFilterReader`] with specific seed to siphash.
    pub fn new(k0: u64, k1: u64, m: u64, p: u8) -> GcsFilterReader {
        GcsFilterReader { filter: GcsFilter::new(k0, k1, p), m }
    }

    /// Returns true if any query matches against this [`GcsFilterReader`].
    pub fn match_any<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: io::Read + ?Sized,
    {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder).unwrap_or(VarInt(0));
        let reader = &mut decoder;
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * self.m;
        let mut mapped =
            query.map(|e| map_to_range(self.filter.hash(e.borrow()), nm)).collect::<Vec<_>>();
        // sort
        mapped.sort_unstable();
        if mapped.is_empty() {
            return Ok(true);
        }
        if n_elements.0 == 0 {
            return Ok(false);
        }

        // find first match in two sorted arrays in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements.0 - 1;
        for p in mapped {
            loop {
                match data.cmp(&p) {
                    Ordering::Equal => return Ok(true),
                    Ordering::Less =>
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        },
                    Ordering::Greater => break,
                }
            }
        }
        Ok(false)
    }

    /// Returns true if all queries match against this [`GcsFilterReader`].
    pub fn match_all<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: io::Read + ?Sized,
    {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder).unwrap_or(VarInt(0));
        let reader = &mut decoder;
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * self.m;
        let mut mapped =
            query.map(|e| map_to_range(self.filter.hash(e.borrow()), nm)).collect::<Vec<_>>();
        // sort
        mapped.sort_unstable();
        mapped.dedup();
        if mapped.is_empty() {
            return Ok(true);
        }
        if n_elements.0 == 0 {
            return Ok(false);
        }

        // figure if all mapped are there in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements.0 - 1;
        for p in mapped {
            loop {
                match data.cmp(&p) {
                    Ordering::Equal => break,
                    Ordering::Less =>
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        },
                    Ordering::Greater => return Ok(false),
                }
            }
        }
        Ok(true)
    }
}

/// Fast reduction of hash to [0, nm) range.
fn map_to_range(hash: u64, nm: u64) -> u64 { ((hash as u128 * nm as u128) >> 64) as u64 }

/// Golomb-Rice encoded filter writer.
pub struct GcsFilterWriter<'a, W> {
    filter: GcsFilter,
    writer: &'a mut W,
    elements: BTreeSet<Vec<u8>>,
    m: u64,
}

impl<'a, W: io::Write> GcsFilterWriter<'a, W> {
    /// Creates a new [`GcsFilterWriter`] wrapping a generic writer, with specific seed to siphash.
    pub fn new(writer: &'a mut W, k0: u64, k1: u64, m: u64, p: u8) -> GcsFilterWriter<'a, W> {
        GcsFilterWriter { filter: GcsFilter::new(k0, k1, p), writer, elements: BTreeSet::new(), m }
    }

    /// Adds data to the filter.
    pub fn add_element(&mut self, element: &[u8]) {
        if !element.is_empty() {
            self.elements.insert(element.to_vec());
        }
    }

    /// Writes the filter to the wrapped writer.
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        let nm = self.elements.len() as u64 * self.m;

        // map hashes to [0, n_elements * M)
        let mut mapped: Vec<_> = self
            .elements
            .iter()
            .map(|e| map_to_range(self.filter.hash(e.as_slice()), nm))
            .collect();
        mapped.sort_unstable();

        // write number of elements as varint
        let mut wrote = VarInt(mapped.len() as u64).consensus_encode(&mut self.writer)?;

        // write out deltas of sorted values into a Golonb-Rice coded bit stream
        let mut writer = BitStreamWriter::new(self.writer);
        let mut last = 0;
        for data in mapped {
            wrote += self.filter.golomb_rice_encode(&mut writer, data - last)?;
            last = data;
        }
        wrote += writer.flush()?;
        Ok(wrote)
    }
}

/// Golomb Coded Set Filter.
struct GcsFilter {
    k0: u64, // sip hash key
    k1: u64, // sip hash key
    p: u8,
}

impl GcsFilter {
    /// Creates a new [`GcsFilter`].
    fn new(k0: u64, k1: u64, p: u8) -> GcsFilter { GcsFilter { k0, k1, p } }

    /// Golomb-Rice encodes a number `n` to a bit stream (parameter 2^k).
    fn golomb_rice_encode<W>(
        &self,
        writer: &mut BitStreamWriter<'_, W>,
        n: u64,
    ) -> Result<usize, io::Error>
    where
        W: io::Write,
    {
        let mut wrote = 0;
        let mut q = n >> self.p;
        while q > 0 {
            let nbits = cmp::min(q, 64);
            wrote += writer.write(!0u64, nbits as u8)?;
            q -= nbits;
        }
        wrote += writer.write(0, 1)?;
        wrote += writer.write(n, self.p)?;
        Ok(wrote)
    }

    /// Golomb-Rice decodes a number from a bit stream (parameter 2^k).
    fn golomb_rice_decode<R>(&self, reader: &mut BitStreamReader<R>) -> Result<u64, io::Error>
    where
        R: io::Read,
    {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(self.p)?;
        Ok((q << self.p) + r)
    }

    /// Hashes an arbitrary slice with siphash using parameters of this filter.
    fn hash(&self, element: &[u8]) -> u64 {
        siphash24::Hash::hash_to_u64_with_keys(self.k0, self.k1, element)
    }
}

/// Bitwise stream reader.
pub struct BitStreamReader<'a, R> {
    buffer: [u8; 1],
    offset: u8,
    reader: &'a mut R,
}

impl<'a, R: io::Read> BitStreamReader<'a, R> {
    /// Creates a new [`BitStreamReader`] that reads bitwise from a given `reader`.
    pub fn new(reader: &'a mut R) -> BitStreamReader<'a, R> {
        BitStreamReader { buffer: [0u8], reader, offset: 8 }
    }

    /// Reads nbit bits, returning the bits in a `u64` starting with the rightmost bit.
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::bip158::BitStreamReader;
    /// # let data = vec![0xff];
    /// # let mut input = data.as_slice();
    /// let mut reader = BitStreamReader::new(&mut input); // input contains all 1's
    /// let res = reader.read(1).expect("read failed");
    /// assert_eq!(res, 1_u64);
    /// ```
    pub fn read(&mut self, mut nbits: u8) -> Result<u64, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not read more than 64 bits at once",
            ));
        }
        let mut data = 0u64;
        while nbits > 0 {
            if self.offset == 8 {
                self.reader.read_exact(&mut self.buffer)?;
                self.offset = 0;
            }
            let bits = cmp::min(8 - self.offset, nbits);
            data <<= bits;
            data |= ((self.buffer[0] << self.offset) >> (8 - bits)) as u64;
            self.offset += bits;
            nbits -= bits;
        }
        Ok(data)
    }
}

/// Bitwise stream writer.
pub struct BitStreamWriter<'a, W> {
    buffer: [u8; 1],
    offset: u8,
    writer: &'a mut W,
}

impl<'a, W: io::Write> BitStreamWriter<'a, W> {
    /// Creates a new [`BitStreamWriter`] that writes bitwise to a given `writer`.
    pub fn new(writer: &'a mut W) -> BitStreamWriter<'a, W> {
        BitStreamWriter { buffer: [0u8], writer, offset: 0 }
    }

    /// Writes nbits bits from data.
    pub fn write(&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not write more than 64 bits at once",
            ));
        }
        let mut wrote = 0;
        while nbits > 0 {
            let bits = cmp::min(8 - self.offset, nbits);
            self.buffer[0] |= ((data << (64 - nbits)) >> (64 - 8 + self.offset)) as u8;
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                wrote += self.flush()?;
            }
        }
        Ok(wrote)
    }

    /// flush bits not yet written.
    pub fn flush(&mut self) -> Result<usize, io::Error> {
        if self.offset > 0 {
            self.writer.write_all(&self.buffer)?;
            self.buffer[0] = 0u8;
            self.offset = 0;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use serde_json::Value;

    use super::*;
    use crate::consensus::encode::deserialize;
    use crate::hash_types::BlockHash;
    use crate::internal_macros::hex;
    use crate::ScriptBuf;

    #[test]
    fn test_blockfilters() {
        // test vectors from: https://github.com/jimpo/bitcoin/blob/c7efb652f3543b001b4dd22186a354605b14f47e/src/test/data/blockfilters.json
        let data = include_str!("../tests/data/blockfilters.json");

        let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
        for t in testdata.iter().skip(1) {
            let block_hash = t.get(1).unwrap().as_str().unwrap().parse::<BlockHash>().unwrap();
            let block: Block = deserialize(&hex!(t.get(2).unwrap().as_str().unwrap())).unwrap();
            assert_eq!(block.block_hash(), block_hash);
            let scripts = t.get(3).unwrap().as_array().unwrap();
            let previous_filter_header =
                t.get(4).unwrap().as_str().unwrap().parse::<FilterHeader>().unwrap();
            let filter_content = hex!(t.get(5).unwrap().as_str().unwrap());
            let filter_header =
                t.get(6).unwrap().as_str().unwrap().parse::<FilterHeader>().unwrap();

            let mut txmap = HashMap::new();
            let mut si = scripts.iter();
            for tx in block.txdata.iter().skip(1) {
                for input in tx.input.iter() {
                    txmap.insert(
                        input.previous_output,
                        ScriptBuf::from(hex!(si.next().unwrap().as_str().unwrap())),
                    );
                }
            }

            let filter = BlockFilter::new_script_filter(&block, |o| {
                if let Some(s) = txmap.get(o) {
                    Ok(s.clone())
                } else {
                    Err(Error::UtxoMissing(*o))
                }
            })
            .unwrap();

            let test_filter = BlockFilter::new(filter_content.as_slice());

            assert_eq!(test_filter.content, filter.content);

            let block_hash = &block.block_hash();
            assert!(filter
                .match_all(
                    block_hash,
                    &mut txmap.iter().filter_map(|(_, s)| if !s.is_empty() {
                        Some(s.as_bytes())
                    } else {
                        None
                    })
                )
                .unwrap());

            for script in txmap.values() {
                let query = vec![script];
                if !script.is_empty() {
                    assert!(filter
                        .match_any(block_hash, &mut query.iter().map(|s| s.as_bytes()))
                        .unwrap());
                }
            }

            assert_eq!(filter_header, filter.filter_header(&previous_filter_header));
        }
    }

    #[test]
    fn test_filter() {
        let mut patterns = BTreeSet::new();

        patterns.insert(hex!("000000"));
        patterns.insert(hex!("111111"));
        patterns.insert(hex!("222222"));
        patterns.insert(hex!("333333"));
        patterns.insert(hex!("444444"));
        patterns.insert(hex!("555555"));
        patterns.insert(hex!("666666"));
        patterns.insert(hex!("777777"));
        patterns.insert(hex!("888888"));
        patterns.insert(hex!("999999"));
        patterns.insert(hex!("aaaaaa"));
        patterns.insert(hex!("bbbbbb"));
        patterns.insert(hex!("cccccc"));
        patterns.insert(hex!("dddddd"));
        patterns.insert(hex!("eeeeee"));
        patterns.insert(hex!("ffffff"));

        let mut out = Vec::new();
        {
            let mut writer = GcsFilterWriter::new(&mut out, 0, 0, M, P);
            for p in &patterns {
                writer.add_element(p.as_slice());
            }
            writer.finish().unwrap();
        }

        let bytes = out;

        {
            let query = vec![hex!("abcdef"), hex!("eeeeee")];
            let reader = GcsFilterReader::new(0, 0, M, P);
            assert!(reader
                .match_any(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
        {
            let query = vec![hex!("abcdef"), hex!("123456")];
            let reader = GcsFilterReader::new(0, 0, M, P);
            assert!(!reader
                .match_any(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
        {
            let reader = GcsFilterReader::new(0, 0, M, P);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p.clone());
            }
            assert!(reader
                .match_all(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
        {
            let reader = GcsFilterReader::new(0, 0, M, P);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p.clone());
            }
            query.push(hex!("abcdef"));
            assert!(!reader
                .match_all(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
    }

    #[test]
    fn test_bit_stream() {
        let mut out = Vec::new();
        {
            let mut writer = BitStreamWriter::new(&mut out);
            writer.write(0, 1).unwrap(); // 0
            writer.write(2, 2).unwrap(); // 10
            writer.write(6, 3).unwrap(); // 110
            writer.write(11, 4).unwrap(); // 1011
            writer.write(1, 5).unwrap(); // 00001
            writer.write(32, 6).unwrap(); // 100000
            writer.write(7, 7).unwrap(); // 0000111
            writer.flush().unwrap();
        }
        let bytes = out;
        assert_eq!(
            "01011010110000110000000001110000",
            format!("{:08b}{:08b}{:08b}{:08b}", bytes[0], bytes[1], bytes[2], bytes[3])
        );
        {
            let mut input = bytes.as_slice();
            let mut reader = BitStreamReader::new(&mut input);
            assert_eq!(reader.read(1).unwrap(), 0);
            assert_eq!(reader.read(2).unwrap(), 2);
            assert_eq!(reader.read(3).unwrap(), 6);
            assert_eq!(reader.read(4).unwrap(), 11);
            assert_eq!(reader.read(5).unwrap(), 1);
            assert_eq!(reader.read(6).unwrap(), 32);
            assert_eq!(reader.read(7).unwrap(), 7);
            // 4 bits remained
            assert!(reader.read(5).is_err());
        }
    }
}
