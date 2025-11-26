// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Client Side Block Filtering network messages.
//!
//! This module describes BIP-0157 Client Side Block Filtering network messages.

use alloc::vec::Vec;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use primitives::BlockHash;
use hashes::{sha256d, HashEngine};
use units::BlockHeight;

use crate::consensus::impl_consensus_encoding;

hashes::hash_newtype! {
    /// Filter hash, as defined in BIP-0157.
    pub struct FilterHash(pub sha256d::Hash);
    /// Filter header, as defined in BIP-0157.
    pub struct FilterHeader(pub sha256d::Hash);
}

hashes::impl_hex_for_newtype!(FilterHash, FilterHeader);

impl FilterHash {
    /// Computes the filter header from a filter hash and previous filter header.
    pub fn filter_header(&self, previous_filter_header: FilterHeader) -> FilterHeader {
        let mut engine = sha256d::Hash::engine();
        engine.input(self.as_ref());
        engine.input(previous_filter_header.as_ref());
        FilterHeader(sha256d::Hash::from_engine(engine))
    }
}

#[rustfmt::skip]
macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl bitcoin::consensus::Encodable for $hashtype {
            fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, w: &mut W) -> core::result::Result<usize, bitcoin::io::Error> {
                self.as_byte_array().consensus_encode(w)
            }
        }

        impl bitcoin::consensus::Decodable for $hashtype {
            fn consensus_decode<R: bitcoin::io::BufRead + ?Sized>(r: &mut R) -> core::result::Result<Self, bitcoin::consensus::encode::Error> {
                Ok(Self::from_byte_array(<<$hashtype as hashes::Hash>::Bytes>::consensus_decode(r)?))
            }
        }
    };
}

impl_hashencode!(FilterHash);
impl_hashencode!(FilterHeader);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

/// getcfilters message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFilters {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: BlockHeight,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}
impl_consensus_encoding!(GetCFilters, filter_type, start_height, stop_hash);

/// cfilter message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CFilter {
    /// Byte identifying the type of filter being returned
    pub filter_type: u8,
    /// Block hash of the Bitcoin block for which the filter is being returned
    pub block_hash: BlockHash,
    /// The serialized compact filter for this block
    pub filter: Vec<u8>,
}
impl_consensus_encoding!(CFilter, filter_type, block_hash, filter);

/// getcfheaders message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFHeaders {
    /// Byte identifying the type of filter being returned
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: BlockHeight,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}
impl_consensus_encoding!(GetCFHeaders, filter_type, start_height, stop_hash);

/// cfheaders message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CFHeaders {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
    /// The filter header preceding the first block in the requested range
    pub previous_filter_header: FilterHeader,
    /// The filter hashes for each block in the requested range
    pub filter_hashes: Vec<FilterHash>,
}
impl_consensus_encoding!(CFHeaders, filter_type, stop_hash, previous_filter_header, filter_hashes);

/// getcfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}
impl_consensus_encoding!(GetCFCheckpt, filter_type, stop_hash);

/// cfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
    /// The filter headers at intervals of 1,000
    pub filter_headers: Vec<FilterHeader>,
}
impl_consensus_encoding!(CFCheckpt, filter_type, stop_hash, filter_headers);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetCFilters {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            start_height: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CFilter {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            block_hash: u.arbitrary()?,
            filter: Vec::<u8>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetCFHeaders {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            start_height: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CFHeaders {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
            previous_filter_header: u.arbitrary()?,
            filter_hashes: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetCFCheckpt {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { filter_type: u.arbitrary()?, stop_hash: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CFCheckpt {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
            filter_headers: Vec::<FilterHeader>::arbitrary(u)?,
        })
    }
}
