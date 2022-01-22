//! Bitcoin Client Side Block Filtering network messages.
//!
//! This module describes BIP157 Client Side Block Filtering network messages.
//!

use bitcoin_derive::{Decodable, Encodable};

use hash_types::{BlockHash, FilterHash, FilterHeader};
use consensus::{encode, Decodable, Encodable, MAX_VEC_SIZE};
use io;

/// getcfilters message
#[derive(PartialEq, Eq, Clone, Debug, Decodable, Encodable)]
pub struct GetCFilters {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: u32,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}

/// cfilter message
#[derive(PartialEq, Eq, Clone, Debug, Decodable, Encodable)]
pub struct CFilter {
    /// Byte identifying the type of filter being returned
    pub filter_type: u8,
    /// Block hash of the Bitcoin block for which the filter is being returned
    pub block_hash: BlockHash,
    /// The serialized compact filter for this block
    pub filter: Vec<u8>,
}

/// getcfheaders message
#[derive(PartialEq, Eq, Clone, Debug, Decodable, Encodable)]
pub struct GetCFHeaders {
    /// Byte identifying the type of filter being returned
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: u32,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}

/// cfheaders message
#[derive(PartialEq, Eq, Clone, Debug, Decodable, Encodable)]
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

/// getcfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug, Decodable, Encodable)]
pub struct GetCFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}

/// cfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug, Decodable, Encodable)]
pub struct CFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
    /// The filter headers at intervals of 1,000
    pub filter_headers: Vec<FilterHeader>,
}
