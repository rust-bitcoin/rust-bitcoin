// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus-encodable types.
//!
//! This is basically a replacement of the `Encodable` trait which does
//! normalization of endianness etc., to ensure that the encoding matches
//! the network consensus encoding.
//!
//! Essentially, anything that must go on the _disk_ or _network_ must be
//! encoded using the `Encodable` trait, since this data must be the same for
//! all systems. Any data going to the _user_ e.g., over JSONRPC, should use the
//! ordinary `Encodable` trait. (This should also be the same across systems, of
//! course, but has some critical differences from the network format e.g.,
//! scripts come with an opcode decode, hashes are big-endian, numbers are
//! typically big-endian decimals, etc.)
//!

use core::{mem, u32};

use hashes::{sha256d, Hash};
use io::{BufRead, Read, Write};

use crate::bip152::{PrefilledTransaction, ShortId};
use crate::bip158::{FilterHash, FilterHeader};
use crate::blockdata::block::{self, BlockHash, TxMerkleNode};
use crate::blockdata::transaction::{Transaction, TxIn, TxOut};
#[cfg(feature = "std")]
use crate::p2p::{
    address::{AddrV2Message, Address},
    message_blockdata::Inventory,
};
use crate::prelude::*;
use crate::taproot::TapLeafHash;

pub use consensus_encoding::*;

/// Data and a 4-byte checksum.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData {
    data: Vec<u8>,
    checksum: [u8; 4],
}

impl CheckedData {
    /// Creates a new `CheckedData` computing the checksum of given data.
    pub fn new(data: Vec<u8>) -> Self {
        let checksum = sha2_checksum(&data);
        Self { data, checksum }
    }

    /// Returns a reference to the raw data without the checksum.
    pub fn data(&self) -> &[u8] { &self.data }

    /// Returns the raw data without the checksum.
    pub fn into_data(self) -> Vec<u8> { self.data }

    /// Returns the checksum of the data.
    pub fn checksum(&self) -> [u8; 4] { self.checksum }
}

impl_vec!(BlockHash);
impl_vec!(block::Header);
impl_vec!(FilterHash);
impl_vec!(FilterHeader);
impl_vec!(TxMerkleNode);
impl_vec!(Transaction);
impl_vec!(TxOut);
impl_vec!(TxIn);
impl_vec!(TapLeafHash);
impl_vec!(VarInt);
impl_vec!(ShortId);
impl_vec!(PrefilledTransaction);

#[cfg(feature = "std")]
impl_vec!(Inventory);
#[cfg(feature = "std")]
impl_vec!((u32, Address));
#[cfg(feature = "std")]
impl_vec!(AddrV2Message);

pub(crate) fn consensus_encode_with_size<W: Write + ?Sized>(
    data: &[u8],
    w: &mut W,
) -> Result<usize, io::Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(w)?;
    w.emit_slice(data)?;
    Ok(vi_len + data.len())
}

struct ReadBytesFromFiniteReaderOpts {
    len: usize,
    chunk_size: usize,
}

/// Read `opts.len` bytes from reader, where `opts.len` could potentially be malicious.
///
/// This function relies on reader being bound in amount of data
/// it returns for OOM protection. See [`Decodable::consensus_decode_from_finite_reader`].
#[inline]
fn read_bytes_from_finite_reader<D: Read + ?Sized>(
    d: &mut D,
    mut opts: ReadBytesFromFiniteReaderOpts,
) -> Result<Vec<u8>, Error> {
    let mut ret = vec![];

    assert_ne!(opts.chunk_size, 0);

    while opts.len > 0 {
        let chunk_start = ret.len();
        let chunk_size = core::cmp::min(opts.len, opts.chunk_size);
        let chunk_end = chunk_start + chunk_size;
        ret.resize(chunk_end, 0u8);
        d.read_slice(&mut ret[chunk_start..chunk_end])?;
        opts.len -= chunk_size;
    }

    Ok(ret)
}

/// Does a double-SHA256 on `data` and returns the first 4 bytes.
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        u32::try_from(self.data.len())
            .expect("network message use u32 as length")
            .consensus_encode(w)?;
        self.checksum().consensus_encode(w)?;
        w.emit_slice(&self.data)?;
        Ok(8 + self.data.len())
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let len = u32::consensus_decode_from_finite_reader(r)? as usize;

        let checksum = <[u8; 4]>::consensus_decode_from_finite_reader(r)?;
        let opts = ReadBytesFromFiniteReaderOpts { len, chunk_size: MAX_VEC_SIZE };
        let data = read_bytes_from_finite_reader(r, opts)?;
        let expected_checksum = sha2_checksum(&data);
        if expected_checksum != checksum {
            Err(self::Error::InvalidChecksum { expected: expected_checksum, actual: checksum })
        } else {
            Ok(CheckedData { data, checksum })
        }
    }
}

impl Encodable for TapLeafHash {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for TapLeafHash {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use core::mem::discriminant;
    use core::fmt;

    use super::*;

    #[test]
    fn serialize_checkeddata_test() {
        let cd = CheckedData::new(vec![1u8, 2, 3, 4, 5]);
        assert_eq!(serialize(&cd), vec![5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn deserialize_vec_test() {
        assert_eq!(deserialize(&[3u8, 2, 3, 4]).ok(), Some(vec![2u8, 3, 4]));
        assert!((deserialize(&[4u8, 2, 3, 4, 5, 6]) as Result<Vec<u8>, _>).is_err());
        // found by cargo fuzz
        assert!(deserialize::<Vec<u64>>(&[
            0xff, 0xff, 0xff, 0xff, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
            0x6b, 0x6b, 0xa, 0xa, 0x3a
        ])
        .is_err());

        let rand_io_err = Error::Io(io::Error::new(io::ErrorKind::Other, ""));

        // Check serialization that `if len > MAX_VEC_SIZE {return err}` isn't inclusive,
        // by making sure it fails with IO Error and not an `OversizedVectorAllocation` Error.
        let err =
            deserialize::<CheckedData>(&serialize(&(super::MAX_VEC_SIZE as u32))).unwrap_err();
        assert_eq!(discriminant(&err), discriminant(&rand_io_err));

        test_len_is_max_vec::<u8>();
        test_len_is_max_vec::<BlockHash>();
        test_len_is_max_vec::<FilterHash>();
        test_len_is_max_vec::<TxMerkleNode>();
        test_len_is_max_vec::<Transaction>();
        test_len_is_max_vec::<TxOut>();
        test_len_is_max_vec::<TxIn>();
        test_len_is_max_vec::<Vec<u8>>();
        test_len_is_max_vec::<u64>();
        #[cfg(feature = "std")]
        test_len_is_max_vec::<(u32, Address)>();
        #[cfg(feature = "std")]
        test_len_is_max_vec::<Inventory>();
    }

    fn test_len_is_max_vec<T>()
    where
        Vec<T>: Decodable,
        T: fmt::Debug,
    {
        let rand_io_err = Error::Io(io::Error::new(io::ErrorKind::Other, ""));
        let varint = VarInt((super::MAX_VEC_SIZE / mem::size_of::<T>()) as u64);
        let err = deserialize::<Vec<T>>(&serialize(&varint)).unwrap_err();
        assert_eq!(discriminant(&err), discriminant(&rand_io_err));
    }

    #[test]
    fn deserialize_checkeddata_test() {
        let cd: Result<CheckedData, _> =
            deserialize(&[5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
        assert_eq!(cd.ok(), Some(CheckedData::new(vec![1u8, 2, 3, 4, 5])));
    }
}
