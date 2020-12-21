// Rust Bitcoin Library
// Written in 2020 by
//     rust-bitcoin developers
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Utility for key Sorting
//!
//! Sort `bitcoin::PublicKey` according to the logic implemented in
//! bitcoin core. In bitcoin core, keys are merely wrappers over
//! bytes and the comparison function directly checks the underlying
//! bytes.
//! When keys are compressed, this utility can be used for BIP67
//! comparison.
use std::cmp;

use PublicKey;

/// Utility structure for representing ordering of PublicKeys
/// as implemented in bitcoin core. Compares the underlying
/// bytes when comparing the two PublicKeys in compressed form
/// instead of naturally derived order which compares underlying
/// 64 byte secp key.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SortKey<'pk>(&'pk PublicKey);

impl<'pk> From<&'pk PublicKey> for SortKey<'pk> {
    fn from(pk: &'pk PublicKey) -> Self {
        SortKey(pk)
    }
}

impl<'pk> cmp::Ord for SortKey<'pk> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self.0.compressed, other.0.compressed) {
            (true, false) => cmp::Ordering::Less,
            (false, true) => cmp::Ordering::Greater,
            (true, true) => self.0.key.serialize().cmp(&other.0.key.serialize()),
            (false, false) => self
                .0
                .key
                .serialize_uncompressed()
                .cmp(&other.0.key.serialize_uncompressed()),
        }
    }
}

impl<'pk> PartialOrd for SortKey<'pk> {
    fn partial_cmp(&self, other: &SortKey) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Compare two bitcoin keys as per ordering defined in bitcoin core.
/// Compares the underlying byte representation of PublicKey
pub fn cmp(pk1: &PublicKey, pk2: &PublicKey) -> cmp::Ordering {
    cmp::Ord::cmp(&SortKey::from(pk1), &SortKey::from(pk2))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    #[test]
    fn test_sortkey_order() {
        let mut slice: [PublicKey; 3] = [
            PublicKey::from_str(
                "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
            )
            .unwrap(),
            PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap(),
            PublicKey::from_str(
                "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
            ).unwrap()
        ];
        slice[..].sort_by(super::cmp);
    }
}
