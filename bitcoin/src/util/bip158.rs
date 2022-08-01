// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

// This module was largely copied from https://github.com/rust-bitcoin/murmel/blob/master/src/blockfilter.rs
// on 11. June 2019 which is licensed under Apache, that file specifically
// was written entirely by Tamas Blummer, who is re-licensing its contents here as CC0.

//! BIP158 Compact Block Filters for light clients.
//!
//! This module implements a structure for compact filters on block data, for
//! use in the BIP 157 light client protocol. The filter construction proposed
//! is an alternative to Bloom filters, as used in BIP 37, that minimizes filter
//! size by using Golomb-Rice coding for compression.
//!
//! ## Example
//!
//! ```ignore
//! fn get_script_for_coin(coin: &OutPoint) -> Result<Script, BlockFilterError> {
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
//! let query: Iterator<Item=Script> = // .. some scripts you care about
//! if filter.match_any(&block_hash, &mut query.map(|s| s.as_bytes())) {
//!   // get this block
//! }
//!  ```
//!

use crate::prelude::*;

use crate::io::{self, Cursor};
use core::fmt::{self, Display, Formatter};
use core::cmp::{self, Ordering};

use crate::hashes::{Hash, siphash24};
use crate::hash_types::{BlockHash, FilterHash, FilterHeader};

use crate::blockdata::block::Block;
use crate::blockdata::script::Script;
use crate::blockdata::transaction::OutPoint;
use crate::consensus::{Decodable, Encodable};
use crate::consensus::encode::VarInt;
use crate::util::endian;
use crate::internal_macros::write_err;

/// Golomb encoding parameter as in BIP-158, see also https://gist.github.com/sipa/576d5f09c3b86c3b1b75598d799fc845
const P: u8 = 19;
const M: u64 = 784931;

/// Errors for blockfilter
#[derive(Debug)]
pub enum Error {
    /// missing UTXO, can not calculate script filter
    UtxoMissing(OutPoint),
    /// some IO error reading or writing binary serialization of the filter
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
    fn from(io: io::Error) -> Self {
        Error::Io(io)
    }
}


/// a computed or read block filter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFilter {
    /// Golomb encoded filter
    pub content: Vec<u8>
}

impl FilterHash {
    /// compute the filter header from a filter hash and previous filter header
    pub fn filter_header(&self, previous_filter_header: &FilterHeader) -> FilterHeader {
        let mut header_data = [0u8; 64];
        header_data[0..32].copy_from_slice(&self[..]);
        header_data[32..64].copy_from_slice(&previous_filter_header[..]);
        FilterHeader::hash(&header_data)
    }
}

impl BlockFilter {
    /// compute this filter's id in a chain of filters
    pub fn filter_header(&self, previous_filter_header: &FilterHeader) -> FilterHeader {
        let filter_hash = FilterHash::hash(self.content.as_slice());
        filter_hash.filter_header(previous_filter_header)
    }

    /// create a new filter from pre-computed data
    pub fn new (content: &[u8]) -> BlockFilter {
        BlockFilter { content: content.to_vec() }
    }

    /// Compute a SCRIPT_FILTER that contains spent and output scripts
    pub fn new_script_filter<M>(block: &Block, script_for_coin: M) -> Result<BlockFilter, Error>
        where M: Fn(&OutPoint) -> Result<Script, Error> {
        let mut out = Vec::new();
        {
            let mut writer = BlockFilterWriter::new(&mut out, block);
            writer.add_output_scripts();
            writer.add_input_scripts(script_for_coin)?;
            writer.finish()?;
        }
        Ok(BlockFilter { content: out })
    }

    /// match any query pattern
    pub fn match_any(&self, block_hash: &BlockHash, query: &mut dyn Iterator<Item=&[u8]>) -> Result<bool, Error> {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_any(&mut Cursor::new(self.content.as_slice()), query)
    }

    /// match all query pattern
    pub fn match_all(&self, block_hash: &BlockHash, query: &mut dyn Iterator<Item=&[u8]>) -> Result<bool, Error> {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_all(&mut Cursor::new(self.content.as_slice()), query)
    }
}

/// Compiles and writes a block filter
pub struct BlockFilterWriter<'a> {
    block: &'a Block,
    writer: GCSFilterWriter<'a>,
}

impl<'a> BlockFilterWriter<'a> {
    /// Create a block filter writer
    pub fn new(writer: &'a mut dyn io::Write, block: &'a Block) -> BlockFilterWriter<'a> {
        let block_hash_as_int = block.block_hash().into_inner();
        let k0 = endian::slice_to_u64_le(&block_hash_as_int[0..8]);
        let k1 = endian::slice_to_u64_le(&block_hash_as_int[8..16]);
        let writer = GCSFilterWriter::new(writer, k0, k1, M, P);
        BlockFilterWriter { block, writer }
    }

    /// Add output scripts of the block - excluding OP_RETURN scripts
    pub fn add_output_scripts(&mut self) {
        for transaction in &self.block.txdata {
            for output in &transaction.output {
                if !output.script_pubkey.is_op_return() {
                    self.add_element(output.script_pubkey.as_bytes());
                }
            }
        }
    }

    /// Add consumed output scripts of a block to filter
    pub fn add_input_scripts<M>(&mut self, script_for_coin: M) -> Result<(), Error>
        where M: Fn(&OutPoint) -> Result<Script, Error> {
        for script in self.block.txdata.iter()
            .skip(1) // skip coinbase
            .flat_map(|t| t.input.iter().map(|i| &i.previous_output))
            .map(script_for_coin) {
            match script {
                Ok(script) => self.add_element(script.as_bytes()),
                Err(e) => return Err(e)
            }
        }
        Ok(())
    }

    /// Add arbitrary element to a filter
    pub fn add_element(&mut self, data: &[u8]) {
        self.writer.add_element(data);
    }

    /// Write block filter
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        self.writer.finish()
    }
}


/// Reads and interpret a block filter
pub struct BlockFilterReader {
    reader: GCSFilterReader
}

impl BlockFilterReader {
    /// Create a block filter reader
    pub fn new(block_hash: &BlockHash) -> BlockFilterReader {
        let block_hash_as_int = block_hash.into_inner();
        let k0 = endian::slice_to_u64_le(&block_hash_as_int[0..8]);
        let k1 = endian::slice_to_u64_le(&block_hash_as_int[8..16]);
        BlockFilterReader { reader: GCSFilterReader::new(k0, k1, M, P) }
    }

    /// match any query pattern
    pub fn match_any(&self, reader: &mut dyn io::Read, query: &mut dyn Iterator<Item=&[u8]>) -> Result<bool, Error> {
        self.reader.match_any(reader, query)
    }

    /// match all query pattern
    pub fn match_all(&self, reader: &mut dyn io::Read, query: &mut dyn Iterator<Item=&[u8]>) -> Result<bool, Error> {
        self.reader.match_all(reader, query)
    }
}


/// Golomb-Rice encoded filter reader
pub struct GCSFilterReader {
    filter: GCSFilter,
    m: u64
}

impl GCSFilterReader {
    /// Create a new filter reader with specific seed to siphash
    pub fn new(k0: u64, k1: u64, m: u64, p: u8) -> GCSFilterReader {
        GCSFilterReader { filter: GCSFilter::new(k0, k1, p), m }
    }

    /// match any query pattern
    pub fn match_any(&self, reader: &mut dyn io::Read, query: &mut dyn Iterator<Item=&[u8]>) -> Result<bool, Error> {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder).unwrap_or(VarInt(0));
        let reader = &mut decoder;
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * self.m;
        let mut mapped = query.map(|e| map_to_range(self.filter.hash(e), nm)).collect::<Vec<_>>();
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
                    Ordering::Less => {
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        }
                    }
                    Ordering::Greater => break,
                }
            }
        }
        Ok(false)
    }

    /// match all query pattern
    pub fn match_all(&self, reader: &mut dyn io::Read, query: &mut dyn Iterator<Item=&[u8]>) -> Result<bool, Error> {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder).unwrap_or(VarInt(0));
        let reader = &mut decoder;
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * self.m;
        let mut mapped = query.map(|e| map_to_range(self.filter.hash(e), nm)).collect::<Vec<_>>();
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
                    Ordering::Less => {
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        }
                    },
                    Ordering::Greater => return Ok(false),
                }
            }
        }
        Ok(true)
    }
}

// fast reduction of hash to [0, nm) range
fn map_to_range(hash: u64, nm: u64) -> u64 {
    ((hash as u128 * nm as u128) >> 64) as u64
}

/// Colomb-Rice encoded filter writer
pub struct GCSFilterWriter<'a> {
    filter: GCSFilter,
    writer: &'a mut dyn io::Write,
    elements: HashSet<Vec<u8>>,
    m: u64
}

impl<'a> GCSFilterWriter<'a> {
    /// Create a new GCS writer wrapping a generic writer, with specific seed to siphash
    pub fn new(writer: &'a mut dyn io::Write, k0: u64, k1: u64, m: u64, p: u8) -> GCSFilterWriter<'a> {
        GCSFilterWriter {
            filter: GCSFilter::new(k0, k1, p),
            writer,
            elements: HashSet::new(),
            m
        }
    }

    /// Add some data to the filter
    pub fn add_element(&mut self, element: &[u8]) {
        if !element.is_empty() {
            self.elements.insert(element.to_vec());
        }
    }

    /// write the filter to the wrapped writer
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        let nm = self.elements.len() as u64 * self.m;

        // map hashes to [0, n_elements * M)
        let mut mapped: Vec<_> = self.elements.iter()
            .map(|e| map_to_range(self.filter.hash(e.as_slice()), nm)).collect();
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

/// Golomb Coded Set Filter
struct GCSFilter {
    k0: u64, // sip hash key
    k1: u64, // sip hash key
    p: u8
}

impl GCSFilter {
    /// Create a new filter
    fn new(k0: u64, k1: u64, p: u8) -> GCSFilter {
        GCSFilter { k0, k1, p }
    }

    /// Golomb-Rice encode a number n to a bit stream (Parameter 2^k)
    fn golomb_rice_encode(&self, writer: &mut BitStreamWriter, n: u64) -> Result<usize, io::Error> {
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

    /// Golomb-Rice decode a number from a bit stream (Parameter 2^k)
    fn golomb_rice_decode(&self, reader: &mut BitStreamReader) -> Result<u64, io::Error> {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(self.p)?;
        Ok((q << self.p) + r)
    }

    /// Hash an arbitrary slice with siphash using parameters of this filter
    fn hash(&self, element: &[u8]) -> u64 {
        siphash24::Hash::hash_to_u64_with_keys(self.k0, self.k1, element)
    }
}

/// Bitwise stream reader
pub struct BitStreamReader<'a> {
    buffer: [u8; 1],
    offset: u8,
    reader: &'a mut dyn io::Read,
}

impl<'a> BitStreamReader<'a> {
    /// Create a new BitStreamReader that reads bitwise from a given reader
    pub fn new(reader: &'a mut dyn io::Read) -> BitStreamReader {
        BitStreamReader {
            buffer: [0u8],
            reader,
            offset: 8,
        }
    }

    /// Read nbit bits
    pub fn read(&mut self, mut nbits: u8) -> Result<u64, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(io::ErrorKind::Other, "can not read more than 64 bits at once"));
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

/// Bitwise stream writer
pub struct BitStreamWriter<'a> {
    buffer: [u8; 1],
    offset: u8,
    writer: &'a mut dyn io::Write,
}

impl<'a> BitStreamWriter<'a> {
    /// Create a new BitStreamWriter that writes bitwise to a given writer
    pub fn new(writer: &'a mut dyn io::Write) -> BitStreamWriter {
        BitStreamWriter {
            buffer: [0u8],
            writer,
            offset: 0,
        }
    }

    /// Write nbits bits from data
    pub fn write(&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(io::ErrorKind::Other, "can not write more than 64 bits at once"));
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

    /// flush bits not yet written
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
    use crate::io::Cursor;

    use crate::hash_types::BlockHash;
    use crate::hashes::hex::FromHex;

    use super::*;

    extern crate serde_json;
    use self::serde_json::Value;

    use crate::consensus::encode::deserialize;
    use std::collections::HashMap;

    #[test]
    fn test_blockfilters() {

        // test vectors from: https://github.com/jimpo/bitcoin/blob/c7efb652f3543b001b4dd22186a354605b14f47e/src/test/data/blockfilters.json
        let data = include_str!("../../test_data/blockfilters.json");

        let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
        for t in testdata.iter().skip(1) {
            let block_hash = BlockHash::from_hex(t.get(1).unwrap().as_str().unwrap()).unwrap();
            let block: Block = deserialize(&Vec::from_hex(t.get(2).unwrap().as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(block.block_hash(), block_hash);
            let scripts = t.get(3).unwrap().as_array().unwrap();
            let previous_filter_header = FilterHeader::from_hex(t.get(4).unwrap().as_str().unwrap()).unwrap();
            let filter_content = Vec::from_hex(t.get(5).unwrap().as_str().unwrap()).unwrap();
            let filter_header = FilterHeader::from_hex(t.get(6).unwrap().as_str().unwrap()).unwrap();

            let mut txmap = HashMap::new();
            let mut si = scripts.iter();
            for tx in block.txdata.iter().skip(1) {
                for input in tx.input.iter() {
                    txmap.insert(input.previous_output, Script::from(Vec::from_hex(si.next().unwrap().as_str().unwrap()).unwrap()));
                }
            }

            let filter = BlockFilter::new_script_filter(&block,
                                        |o| if let Some(s) = txmap.get(o) {
                                            Ok(s.clone())
                                        } else {
                                            Err(Error::UtxoMissing(*o))
                                        }).unwrap();

            let test_filter = BlockFilter::new(filter_content.as_slice());

            assert_eq!(test_filter.content, filter.content);

            let block_hash = &block.block_hash();
            assert!(filter.match_all(block_hash, &mut txmap.iter()
                .filter_map(|(_, s)| if !s.is_empty() { Some(s.as_bytes()) } else { None })).unwrap());

            for script in txmap.values() {
                let query = vec![script];
                if !script.is_empty () {
                    assert!(filter.match_any(block_hash, &mut query.iter()
                        .map(|s| s.as_bytes())).unwrap());
                }
            }

            assert_eq!(filter_header, filter.filter_header(&previous_filter_header));
        }
    }

    #[test]
    fn test_filter() {
        let mut patterns = HashSet::new();

        patterns.insert(Vec::from_hex("000000").unwrap());
        patterns.insert(Vec::from_hex("111111").unwrap());
        patterns.insert(Vec::from_hex("222222").unwrap());
        patterns.insert(Vec::from_hex("333333").unwrap());
        patterns.insert(Vec::from_hex("444444").unwrap());
        patterns.insert(Vec::from_hex("555555").unwrap());
        patterns.insert(Vec::from_hex("666666").unwrap());
        patterns.insert(Vec::from_hex("777777").unwrap());
        patterns.insert(Vec::from_hex("888888").unwrap());
        patterns.insert(Vec::from_hex("999999").unwrap());
        patterns.insert(Vec::from_hex("aaaaaa").unwrap());
        patterns.insert(Vec::from_hex("bbbbbb").unwrap());
        patterns.insert(Vec::from_hex("cccccc").unwrap());
        patterns.insert(Vec::from_hex("dddddd").unwrap());
        patterns.insert(Vec::from_hex("eeeeee").unwrap());
        patterns.insert(Vec::from_hex("ffffff").unwrap());

        let mut out = Vec::new();
        {
            let mut writer = GCSFilterWriter::new(&mut out, 0, 0, M, P);
            for p in &patterns {
                writer.add_element(p.as_slice());
            }
            writer.finish().unwrap();
        }

        let bytes = out;

        {
            let query = vec![Vec::from_hex("abcdef").unwrap(), Vec::from_hex("eeeeee").unwrap()];
            let reader = GCSFilterReader::new(0, 0, M, P);
            let mut input = Cursor::new(bytes.clone());
            assert!(reader.match_any(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
        }
        {
            let query = vec![Vec::from_hex("abcdef").unwrap(), Vec::from_hex("123456").unwrap()];
            let reader = GCSFilterReader::new(0, 0, M, P);
            let mut input = Cursor::new(bytes.clone());
            assert!(!reader.match_any(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
        }
        {
            let reader = GCSFilterReader::new(0, 0, M, P);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p.clone());
            }
            let mut input = Cursor::new(bytes.clone());
            assert!(reader.match_all(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
        }
        {
            let reader = GCSFilterReader::new(0, 0, M, P);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p.clone());
            }
            query.push(Vec::from_hex("abcdef").unwrap());
            let mut input = Cursor::new(bytes);
            assert!(!reader.match_all(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
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
        assert_eq!("01011010110000110000000001110000", format!("{:08b}{:08b}{:08b}{:08b}", bytes[0], bytes[1], bytes[2], bytes[3]));
        {
            let mut input = Cursor::new(bytes);
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
