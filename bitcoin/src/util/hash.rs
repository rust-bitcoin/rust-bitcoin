// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hash functions.
//!
//! This module provides utility functions related to hashing data, including
//! merkleization.
//!

use core::iter;

use crate::prelude::*;

use crate::io;
use core::cmp::min;

use crate::consensus::encode::Encodable;
use crate::hashes::Hash;

/// Calculates the merkle root of a list of *hashes*, inline (in place) in `hashes`.
///
/// In most cases, you'll want to use [bitcoin_merkle_root] instead.
///
/// # Returns
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn bitcoin_merkle_root_inline<T>(hashes: &mut [T]) -> Option<T>
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
{
    match hashes.len() {
        0 => None,
        1 => Some(hashes[0]),
        _ => Some(merkle_root_r(hashes)),
    }
}

/// Calculates the merkle root of an iterator of *hashes*.
///
/// This fcuntion calculate the root from a merkle path when we need to derive the root from the
/// txs list [bitcoin_merkle_root] should be used.
///
/// # Returns
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn bitcoin_merkle_root_from_path<T, I>(mut hashes: I) -> Option<T>
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
    I: Iterator<Item = T>,
{
    let first = hashes.next()?;
    let second = match hashes.next() {
        Some(second) => second,
        None => return Some(first),
    };

    let mut encoder = T::engine();
    let mut root = first;
    root.consensus_encode(&mut encoder).expect("in-memory writers don't error");
    second.consensus_encode(&mut encoder).expect("in-memory writers don't error");
    root = T::from_engine(encoder);
    for hash in hashes {
        let mut encoder = T::engine();
        root.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hash.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        root = T::from_engine(encoder);
    }
    Some(root)
}

/// Calculates the merkle root of an iterator of *hashes*.
///
/// This fcuntion calculate the root from the list of all the txs in the block when we need to
/// derive the root from the merkle path [bitcoin_merkle_root_from_path] should be used.
///
/// # Returns
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn bitcoin_merkle_root<T, I>(mut hashes: I) -> Option<T>
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
    I: Iterator<Item = T>,
{
    let first = hashes.next()?;
    let second = match hashes.next() {
        Some(second) => second,
        None => return Some(first),
    };

    let mut hashes = iter::once(first).chain(iter::once(second)).chain(hashes);

    // We need a local copy to pass to `merkle_root_r`. It's more efficient to do the first loop of
    // processing as we make the copy instead of copying the whole iterator.
    let (min, max) = hashes.size_hint();
    let mut alloc = Vec::with_capacity(max.unwrap_or(min) / 2 + 1);

    while let Some(hash1) = hashes.next() {
        // If the size is odd, use the last element twice.
        let hash2 = hashes.next().unwrap_or(hash1);
        let mut encoder = T::engine();
        hash1.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hash2.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        alloc.push(T::from_engine(encoder));
    }

    Some(merkle_root_r(&mut alloc))
}

// `hashes` must contain at least one hash.
fn merkle_root_r<T>(hashes: &mut [T]) -> T
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
{
    if hashes.len() == 1 {
        return hashes[0];
    }

    for idx in 0..((hashes.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, hashes.len() - 1);
        let mut encoder = T::engine();
        hashes[idx1].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx2].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx] = T::from_engine(encoder);
    }
    let half_len = hashes.len() / 2 + hashes.len() % 2;

    merkle_root_r(&mut hashes[0..half_len])
}

#[cfg(test)]
mod tests {
    use crate::consensus::encode::deserialize;
    use crate::hashes::sha256d;

    use super::*;
    use crate::blockdata::block::Block;
    use crate::hashes::Hash;

    #[test]
    fn both_merkle_root_functions_return_the_same_result() {
        // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
        let segwit_block = include_bytes!("../../test_data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
        let block: Block = deserialize(&segwit_block[..]).expect("Failed to deserialize block");
        assert!(block.check_merkle_root()); // Sanity check.

        let hashes_iter = block.txdata.iter().map(|obj| obj.txid().as_hash());

        let mut hashes_array: [sha256d::Hash; 15] = [Hash::all_zeros(); 15];
        for (i, hash) in hashes_iter.clone().enumerate() {
            hashes_array[i] = hash;
        }

        let from_iter = bitcoin_merkle_root(hashes_iter);
        let from_array = bitcoin_merkle_root_inline(&mut hashes_array);
        assert_eq!(from_iter, from_array);
    }

    #[test]
    fn test_merkle_root_from_path() {
        let coinbase_hash = [
            10_u8, 66, 217, 241, 152, 86, 5, 234, 225, 85, 251, 215, 105, 1, 21, 126, 222, 69, 40,
            157, 23, 177, 157, 106, 234, 164, 243, 206, 23, 241, 250, 166,
        ];

        let a = [
            122, 97, 64, 124, 164, 158, 164, 14, 87, 119, 226, 169, 34, 196, 251, 51, 31, 131, 109,
            250, 13, 54, 94, 6, 177, 27, 156, 154, 101, 30, 123, 159,
        ];
        let b = [
            180, 113, 121, 253, 215, 85, 129, 38, 108, 2, 86, 66, 46, 12, 131, 139, 130, 87, 29,
            92, 59, 164, 247, 114, 251, 140, 129, 88, 127, 196, 125, 116,
        ];
        let c = [
            171, 77, 225, 148, 80, 32, 41, 157, 246, 77, 161, 49, 87, 139, 214, 236, 149, 164, 192,
            128, 195, 9, 5, 168, 131, 27, 250, 9, 60, 179, 206, 94,
        ];
        let d = [
            6, 187, 202, 75, 155, 220, 255, 166, 199, 35, 182, 220, 20, 96, 123, 41, 109, 40, 186,
            142, 13, 139, 230, 164, 116, 177, 217, 23, 16, 123, 135, 202,
        ];
        let e = [
            109, 45, 171, 89, 223, 39, 132, 14, 150, 128, 241, 113, 136, 227, 105, 123, 224, 48,
            66, 240, 189, 186, 222, 49, 173, 143, 80, 90, 110, 219, 192, 235,
        ];
        let f = [
            196, 7, 21, 180, 228, 161, 182, 132, 28, 153, 242, 12, 210, 127, 157, 86, 62, 123, 181,
            33, 84, 3, 105, 129, 148, 162, 5, 152, 64, 7, 196, 156,
        ];
        let g = [
            22, 16, 18, 180, 109, 237, 68, 167, 197, 10, 195, 134, 11, 119, 219, 184, 49, 140, 239,
            45, 27, 210, 212, 120, 186, 60, 155, 105, 106, 219, 218, 32,
        ];
        let h = [
            83, 228, 21, 241, 42, 240, 8, 254, 109, 156, 59, 171, 167, 46, 183, 60, 27, 63, 241,
            211, 235, 179, 147, 99, 46, 3, 22, 166, 159, 169, 183, 159,
        ];
        let i = [
            230, 81, 3, 190, 66, 73, 200, 55, 94, 135, 209, 50, 92, 193, 114, 202, 141, 170, 124,
            142, 206, 29, 88, 9, 22, 110, 203, 145, 238, 66, 166, 35,
        ];
        let l = [
            43, 106, 86, 239, 237, 74, 208, 202, 247, 133, 88, 42, 15, 77, 163, 186, 85, 26, 89,
            151, 5, 19, 30, 122, 108, 220, 215, 104, 152, 226, 113, 55,
        ];
        let m = [
            148, 76, 200, 221, 206, 54, 56, 45, 252, 60, 123, 202, 195, 73, 144, 65, 168, 184, 59,
            130, 145, 229, 250, 44, 213, 70, 175, 128, 34, 31, 102, 80,
        ];
        let n = [
            203, 112, 102, 31, 49, 147, 24, 25, 245, 61, 179, 146, 205, 127, 126, 100, 78, 204,
            228, 146, 209, 154, 89, 194, 209, 81, 57, 167, 88, 251, 44, 76,
        ];
        let path: Vec<crate::hashes::sha256d::Hash> =
            vec![coinbase_hash, a, b, c, d, e, f, g, h, i, l, m, n]
                .iter()
                .map(|h| crate::hashes::Hash::from_slice(&h[..]).unwrap())
                .collect();
        let expected_root: crate::hashes::sha256d::Hash = crate::hashes::Hash::from_slice(
            &[
                73_u8, 100, 41, 247, 106, 44, 1, 242, 3, 64, 100, 1, 98, 155, 40, 91, 170, 255,
                170, 29, 193, 255, 244, 71, 236, 29, 134, 218, 94, 45, 78, 77,
            ][..],
        )
        .unwrap();
        let root = bitcoin_merkle_root_from_path(path.into_iter()).unwrap();
        assert_eq!(expected_root, root)
    }
}
