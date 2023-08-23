// SPDX-License-Identifier: CC0-1.0

//! Implementations of Encodable/Decodable for various types.

use core::mem;

use hashes::{sha256, sha256d, Hash};

use crate::bip152::{PrefilledTransaction, ShortId};
use crate::blockdata::transaction::{Transaction, TxIn, TxOut};
use crate::consensus::decode::{
    self, Decodable, ReadBytesFromFiniteReaderOpts, ReadExt, MAX_VEC_SIZE,
};
use crate::consensus::encode::{self, Encodable, WriteExt};
use crate::consensus::VarInt;
use crate::hash_types::{BlockHash, FilterHash, FilterHeader, TxMerkleNode};
use crate::io;
#[cfg(feature = "std")]
use crate::p2p::{
    address::{AddrV2Message, Address},
    message_blockdata::Inventory,
};
use crate::prelude::*;
use crate::taproot::TapLeafHash;

// Primitive types
macro_rules! impl_int_encodable {
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => {
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
                ReadExt::$meth_dec(r)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                w.$meth_enc(*self)?;
                Ok(mem::size_of::<$ty>())
            }
        }
    };
}

impl_int_encodable!(u8, read_u8, emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8, read_i8, emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

impl Encodable for bool {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<bool, decode::Error> {
        ReadExt::read_bool(r)
    }
}

impl Encodable for String {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(w)?;
        w.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<String, decode::Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| decode::Error::ParseFailed("String was not valid UTF8"))
    }
}

impl Encodable for Cow<'static, str> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(w)?;
        w.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for Cow<'static, str> {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Cow<'static, str>, decode::Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| decode::Error::ParseFailed("String was not valid UTF8"))
            .map(Cow::Owned)
    }
}

macro_rules! impl_array {
    ( $size:literal ) => {
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<W: WriteExt + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                w.emit_slice(&self[..])?;
                Ok(self.len())
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
                let mut ret = [0; $size];
                r.read_slice(&mut ret)?;
                Ok(ret)
            }
        }
    };
}

impl_array!(2);
impl_array!(4);
impl_array!(6);
impl_array!(8);
impl_array!(10);
impl_array!(12);
impl_array!(16);
impl_array!(32);
impl_array!(33);

impl Encodable for [u16; 8] {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        for c in self.iter() {
            c.consensus_encode(w)?;
        }
        Ok(16)
    }
}

impl Decodable for [u16; 8] {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
        let mut res = [0; 8];
        for item in &mut res {
            *item = Decodable::consensus_decode(r)?;
        }
        Ok(res)
    }
}

macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                let mut len = 0;
                len += VarInt(self.len() as u64).consensus_encode(w)?;
                for c in self.iter() {
                    len += c.consensus_encode(w)?;
                }
                Ok(len)
            }
        }

        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<Self, decode::Error> {
                let len = VarInt::consensus_decode_from_finite_reader(r)?.0;
                // Do not allocate upfront more items than if the sequence of type
                // occupied roughly quarter a block. This should never be the case
                // for normal data, but even if that's not true - `push` will just
                // reallocate.
                // Note: OOM protection relies on reader eventually running out of
                // data to feed us.
                let max_capacity = MAX_VEC_SIZE / 4 / mem::size_of::<$type>();
                let mut ret = Vec::with_capacity(core::cmp::min(len as usize, max_capacity));
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode_from_finite_reader(r)?);
                }
                Ok(ret)
            }
        }
    };
}
impl_vec!(BlockHash);
impl_vec!(FilterHash);
impl_vec!(FilterHeader);
impl_vec!(TxMerkleNode);
impl_vec!(Transaction);
impl_vec!(TxOut);
impl_vec!(TxIn);
impl_vec!(Vec<u8>);
impl_vec!(u64);
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

impl Encodable for Vec<u8> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        encode::consensus_encode_with_size(self, w)
    }
}

impl Decodable for Vec<u8> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, decode::Error> {
        let len = VarInt::consensus_decode(r)?.0 as usize;
        // most real-world vec of bytes data, wouldn't be larger than 128KiB
        let opts = ReadBytesFromFiniteReaderOpts { len, chunk_size: 128 * 1024 };
        decode::read_bytes_from_finite_reader(r, opts)
    }
}

impl Encodable for Box<[u8]> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        encode::consensus_encode_with_size(self, w)
    }
}

impl Decodable for Box<[u8]> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, decode::Error> {
        <Vec<u8>>::consensus_decode_from_finite_reader(r).map(From::from)
    }
}

impl<'a, T: Encodable> Encodable for &'a T {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

impl<'a, T: Encodable> Encodable for &'a mut T {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

impl<T: Encodable> Encodable for rc::Rc<T> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(any(not(rust_v_1_60), target_has_atomic = "ptr"))]
impl<T: Encodable> Encodable for sync::Arc<T> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

macro_rules! tuple_encode {
    ($($x:ident),*) => {
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(w)?;)*
                Ok(len)
            }
        }

        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
                Ok(($({let $x = Decodable::consensus_decode(r)?; $x }),*))
            }
        }
    };
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

impl Encodable for sha256d::Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for sha256d::Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

impl Encodable for sha256::Hash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for sha256::Hash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

impl Encodable for TapLeafHash {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for TapLeafHash {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}
