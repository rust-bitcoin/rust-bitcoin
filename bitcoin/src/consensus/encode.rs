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

// TODO(Tobin): Remove this re-export once consensus refactor is done.
pub use crate::consensus::decode::{self, Decodable, Error, ReadExt, MAX_VEC_SIZE};
// TODO(Tobin): Remove this re-export once consensus refactor is done.
pub use crate::consensus::types::{CheckedData, VarInt};
// TODO(Tobin): Remove this re-export once consensus refactor is done.
pub use crate::consensus::{deserialize, deserialize_partial, serialize, serialize_hex};
use crate::io;

/// Data which can be encoded in a consensus-consistent way.
pub trait Encodable {
    /// Encodes an object with a well-defined format.
    ///
    /// # Returns
    ///
    /// The number of bytes written on success. The only errors returned are errors propagated from
    /// the writer.
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Extensions of `Write` to encode data as per Bitcoin consensus.
pub trait WriteExt: io::Write {
    /// Outputs a 64-bit unsigned integer.
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Outputs a 32-bit unsigned integer.
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Outputs a 16-bit unsigned integer.
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Outputs an 8-bit unsigned integer.
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Outputs a 64-bit signed integer.
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Outputs a 32-bit signed integer.
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Outputs a 16-bit signed integer.
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Outputs an 8-bit signed integer.
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Outputs a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Outputs a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), io::Error> {
            self.write_all(&v.to_le_bytes())
        }
    };
}

impl<W: io::Write + ?Sized> WriteExt for W {
    encoder_fn!(emit_u64, u64);
    encoder_fn!(emit_u32, u32);
    encoder_fn!(emit_u16, u16);
    encoder_fn!(emit_i64, i64);
    encoder_fn!(emit_i32, i32);
    encoder_fn!(emit_i16, i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> { self.write_all(&[v]) }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error> { self.write_all(v) }
}

pub(crate) fn consensus_encode_with_size<W: io::Write + ?Sized>(
    data: &[u8],
    w: &mut W,
) -> Result<usize, io::Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(w)?;
    w.emit_slice(data)?;
    Ok(vi_len + data.len())
}

#[cfg(test)]
mod tests {
    use core::fmt;
    use core::mem::{self, discriminant};

    use super::*;
    use crate::blockdata::transaction::{Transaction, TxIn, TxOut};
    use crate::consensus::decode::ReadBytesFromFiniteReaderOpts;
    use crate::consensus::{deserialize_partial, Decodable, Encodable, VarInt};
    use crate::hash_types::{BlockHash, FilterHash, TxMerkleNode};
    #[cfg(feature = "std")]
    use crate::p2p::{message_blockdata::Inventory, Address};
    use crate::prelude::*;

    #[test]
    fn serialize_int_test() {
        // bool
        assert_eq!(serialize(&false), vec![0u8]);
        assert_eq!(serialize(&true), vec![1u8]);
        // u8
        assert_eq!(serialize(&1u8), vec![1u8]);
        assert_eq!(serialize(&0u8), vec![0u8]);
        assert_eq!(serialize(&255u8), vec![255u8]);
        // u16
        assert_eq!(serialize(&1u16), vec![1u8, 0]);
        assert_eq!(serialize(&256u16), vec![0u8, 1]);
        assert_eq!(serialize(&5000u16), vec![136u8, 19]);
        // u32
        assert_eq!(serialize(&1u32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256u32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000u32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000u32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090u32), vec![10u8, 10, 10, 10]);
        // i32
        assert_eq!(serialize(&-1i32), vec![255u8, 255, 255, 255]);
        assert_eq!(serialize(&-256i32), vec![0u8, 255, 255, 255]);
        assert_eq!(serialize(&-5000i32), vec![120u8, 236, 255, 255]);
        assert_eq!(serialize(&-500000i32), vec![224u8, 94, 248, 255]);
        assert_eq!(serialize(&-168430090i32), vec![246u8, 245, 245, 245]);
        assert_eq!(serialize(&1i32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256i32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000i32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000i32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090i32), vec![10u8, 10, 10, 10]);
        // u64
        assert_eq!(serialize(&1u64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256u64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000u64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000u64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730u64), vec![10u8, 10, 10, 10, 10, 10, 10, 10]);
        // i64
        assert_eq!(serialize(&-1i64), vec![255u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-256i64), vec![0u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-5000i64), vec![120u8, 236, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-500000i64), vec![224u8, 94, 248, 255, 255, 255, 255, 255]);
        assert_eq!(
            serialize(&-723401728380766730i64),
            vec![246u8, 245, 245, 245, 245, 245, 245, 245]
        );
        assert_eq!(serialize(&1i64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256i64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000i64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000i64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730i64), vec![10u8, 10, 10, 10, 10, 10, 10, 10]);
    }

    #[test]
    fn serialize_varint_test() {
        assert_eq!(serialize(&VarInt(10)), vec![10u8]);
        assert_eq!(serialize(&VarInt(0xFC)), vec![0xFCu8]);
        assert_eq!(serialize(&VarInt(0xFD)), vec![0xFDu8, 0xFD, 0]);
        assert_eq!(serialize(&VarInt(0xFFF)), vec![0xFDu8, 0xFF, 0xF]);
        assert_eq!(serialize(&VarInt(0xF0F0F0F)), vec![0xFEu8, 0xF, 0xF, 0xF, 0xF]);
        assert_eq!(
            serialize(&VarInt(0xF0F0F0F0F0E0)),
            vec![0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0]
        );
        assert_eq!(
            test_varint_encode(0xFF, &0x100000000_u64.to_le_bytes()).unwrap(),
            VarInt(0x100000000)
        );
        assert_eq!(test_varint_encode(0xFE, &0x10000_u64.to_le_bytes()).unwrap(), VarInt(0x10000));
        assert_eq!(test_varint_encode(0xFD, &0xFD_u64.to_le_bytes()).unwrap(), VarInt(0xFD));

        // Test that length calc is working correctly
        test_varint_len(VarInt(0), 1);
        test_varint_len(VarInt(0xFC), 1);
        test_varint_len(VarInt(0xFD), 3);
        test_varint_len(VarInt(0xFFFF), 3);
        test_varint_len(VarInt(0x10000), 5);
        test_varint_len(VarInt(0xFFFFFFFF), 5);
        test_varint_len(VarInt(0xFFFFFFFF + 1), 9);
        test_varint_len(VarInt(u64::MAX), 9);
    }

    fn test_varint_len(varint: VarInt, expected: usize) {
        let mut encoder = vec![];
        assert_eq!(varint.consensus_encode(&mut encoder).unwrap(), expected);
        assert_eq!(varint.size(), expected);
    }

    fn test_varint_encode(n: u8, x: &[u8]) -> Result<VarInt, Error> {
        let mut input = [0u8; 9];
        input[0] = n;
        input[1..x.len() + 1].copy_from_slice(x);
        deserialize_partial::<VarInt>(&input).map(|t| t.0)
    }

    #[test]
    fn deserialize_nonminimal_vec() {
        // Check the edges for variant int
        assert_eq!(
            discriminant(
                &test_varint_encode(0xFF, &(0x100000000_u64 - 1).to_le_bytes()).unwrap_err()
            ),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&test_varint_encode(0xFE, &(0x10000_u64 - 1).to_le_bytes()).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&test_varint_encode(0xFD, &(0xFD_u64 - 1).to_le_bytes()).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );

        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0x00, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0x00, 0x00, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0xff, 0x00, 0x00]).unwrap_err()),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(
                &deserialize::<Vec<u8>>(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .unwrap_err()
            ),
            discriminant(&Error::NonMinimalVarInt)
        );
        assert_eq!(
            discriminant(
                &deserialize::<Vec<u8>>(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .unwrap_err()
            ),
            discriminant(&Error::NonMinimalVarInt)
        );

        let mut vec_256 = vec![0; 259];
        vec_256[0] = 0xfd;
        vec_256[1] = 0x00;
        vec_256[2] = 0x01;
        assert!(deserialize::<Vec<u8>>(&vec_256).is_ok());

        let mut vec_253 = vec![0; 256];
        vec_253[0] = 0xfd;
        vec_253[1] = 0xfd;
        vec_253[2] = 0x00;
        assert!(deserialize::<Vec<u8>>(&vec_253).is_ok());
    }

    #[test]
    fn serialize_checkeddata_test() {
        let cd = CheckedData::new(vec![1u8, 2, 3, 4, 5]);
        assert_eq!(serialize(&cd), vec![5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn serialize_vector_test() {
        assert_eq!(serialize(&vec![1u8, 2, 3]), vec![3u8, 1, 2, 3]);
        // TODO: test vectors of more interesting objects
    }

    #[test]
    fn serialize_strbuf_test() {
        assert_eq!(serialize(&"Andrew".to_string()), vec![6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]);
    }

    #[test]
    fn deserialize_int_test() {
        // bool
        assert!((deserialize(&[58u8, 0]) as Result<bool, _>).is_err());
        assert_eq!(deserialize(&[58u8]).ok(), Some(true));
        assert_eq!(deserialize(&[1u8]).ok(), Some(true));
        assert_eq!(deserialize(&[0u8]).ok(), Some(false));
        assert!((deserialize(&[0u8, 1]) as Result<bool, _>).is_err());

        // u8
        assert_eq!(deserialize(&[58u8]).ok(), Some(58u8));

        // u16
        assert_eq!(deserialize(&[0x01u8, 0x02]).ok(), Some(0x0201u16));
        assert_eq!(deserialize(&[0xABu8, 0xCD]).ok(), Some(0xCDABu16));
        assert_eq!(deserialize(&[0xA0u8, 0x0D]).ok(), Some(0xDA0u16));
        let failure16: Result<u16, _> = deserialize(&[1u8]);
        assert!(failure16.is_err());

        // i16
        assert_eq!(deserialize(&[0x32_u8, 0xF4]).ok(), Some(-0x0bce_i16));
        assert_eq!(deserialize(&[0xFF_u8, 0xFE]).ok(), Some(-0x0101_i16));
        assert_eq!(deserialize(&[0x00_u8, 0x00]).ok(), Some(-0_i16));
        assert_eq!(deserialize(&[0xFF_u8, 0xFA]).ok(), Some(-0x0501_i16));

        // u32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABu32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD]).ok(), Some(0xCDAB0DA0u32));

        let failure32: Result<u32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failure32.is_err());

        // i32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABi32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0x2D]).ok(), Some(0x2DAB0DA0i32));

        assert_eq!(deserialize(&[0, 0, 0, 0]).ok(), Some(-0_i32));
        assert_eq!(deserialize(&[0, 0, 0, 0]).ok(), Some(0_i32));

        assert_eq!(deserialize(&[0xFF, 0xFF, 0xFF, 0xFF]).ok(), Some(-1_i32));
        assert_eq!(deserialize(&[0xFE, 0xFF, 0xFF, 0xFF]).ok(), Some(-2_i32));
        assert_eq!(deserialize(&[0x01, 0xFF, 0xFF, 0xFF]).ok(), Some(-255_i32));
        assert_eq!(deserialize(&[0x02, 0xFF, 0xFF, 0xFF]).ok(), Some(-254_i32));

        let failurei32: Result<i32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failurei32.is_err());

        // u64
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABu64));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(0x99000099CDAB0DA0u64)
        );
        let failure64: Result<u64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failure64.is_err());

        // i64
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABi64));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(-0x66ffff663254f260i64)
        );
        assert_eq!(
            deserialize(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-1_i64)
        );
        assert_eq!(
            deserialize(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-2_i64)
        );
        assert_eq!(
            deserialize(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-255_i64)
        );
        assert_eq!(
            deserialize(&[0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-254_i64)
        );

        let failurei64: Result<i64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failurei64.is_err());
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
    fn deserialize_strbuf_test() {
        assert_eq!(
            deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(),
            Some("Andrew".to_string())
        );
        assert_eq!(
            deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(),
            Some(Cow::Borrowed("Andrew"))
        );
    }

    #[test]
    fn deserialize_checkeddata_test() {
        let cd: Result<CheckedData, _> =
            deserialize(&[5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
        assert_eq!(cd.ok(), Some(CheckedData::new(vec![1u8, 2, 3, 4, 5])));
    }

    #[test]
    fn limit_read_test() {
        let witness = vec![vec![0u8; 3_999_999]; 2];
        let ser = serialize(&witness);
        let mut reader = io::Cursor::new(ser);
        let err = Vec::<Vec<u8>>::consensus_decode(&mut reader);
        assert!(err.is_err());
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn serialization_round_trips() {
        use secp256k1::rand::{thread_rng, Rng};

        macro_rules! round_trip {
            ($($val_type:ty),*) => {
                $(
                    let r: $val_type = thread_rng().gen();
                    assert_eq!(deserialize::<$val_type>(&serialize(&r)).unwrap(), r);
                )*
            };
        }
        macro_rules! round_trip_bytes {
            ($(($val_type:ty, $data:expr)),*) => {
                $(
                    thread_rng().fill(&mut $data[..]);
                    assert_eq!(deserialize::<$val_type>(&serialize(&$data)).unwrap()[..], $data[..]);
                )*
            };
        }

        let mut data = Vec::with_capacity(256);
        let mut data64 = Vec::with_capacity(256);
        for _ in 0..10 {
            round_trip! {bool, i8, u8, i16, u16, i32, u32, i64, u64,
            (bool, i8, u16, i32), (u64, i64, u32, i32, u16, i16), (i8, u8, i16, u16, i32, u32, i64, u64),
            [u8; 2], [u8; 4], [u8; 8], [u8; 12], [u8; 16], [u8; 32]};

            data.clear();
            data64.clear();
            let len = thread_rng().gen_range(1..256);
            data.resize(len, 0u8);
            data64.resize(len, 0u64);
            let mut arr33 = [0u8; 33];
            let mut arr16 = [0u16; 8];
            round_trip_bytes! {(Vec<u8>, data), ([u8; 33], arr33), ([u16; 8], arr16), (Vec<u64>, data64)};
        }
    }

    #[test]
    fn test_read_bytes_from_finite_reader() {
        use crate::consensus::decode;

        let data: Vec<u8> = (0..10).collect();

        for chunk_size in 1..20 {
            assert_eq!(
                decode::read_bytes_from_finite_reader(
                    &mut io::Cursor::new(&data),
                    ReadBytesFromFiniteReaderOpts { len: data.len(), chunk_size }
                )
                .unwrap(),
                data
            );
        }
    }
}
