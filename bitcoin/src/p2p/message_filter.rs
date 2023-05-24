// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Client Side Block Filtering network messages.
//!
//! This module describes BIP157 Client Side Block Filtering network messages.
//!

use crate::hash_types::{BlockHash, FilterHash, FilterHeader};
use crate::internal_macros::impl_consensus_encoding;

/// getcfilters message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFilters {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: u32,
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
    pub start_height: u32,
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
