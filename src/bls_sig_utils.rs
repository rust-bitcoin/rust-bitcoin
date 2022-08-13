// Rust Dash Library
// Written by
//   The Rust Dash developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash BLS elements
//! Convenience wrappers around fixed size arrays of 48 and 96 bytes representing the public key
//! and signature.
//!

use core::{fmt};

impl_array_newtype!(BLSPublicKey, u8, 48);
impl_bytes_newtype!(BLSPublicKey, 48);
/// A BLS Public key is 48 bytes in the scheme used for Dash Core
#[rustversion::attr(since(1.48), derive(PartialEq, Eq, Ord, PartialOrd, Hash))]
#[derive(Clone)]
pub struct BLSPublicKey([u8;48]);

impl_array_newtype!(BLSSignature, u8, 96);
impl_bytes_newtype!(BLSSignature, 96);

/// A BLS Signature is 96 bytes in the scheme used for Dash Core
#[rustversion::attr(since(1.48), derive(PartialEq, Eq, Ord, PartialOrd, Hash))]
#[derive(Clone)]
pub struct BLSSignature([u8;96]);


macro_rules! impl_elementencode {
    ($element:ident, $len:expr) => {
        impl $crate::consensus::Encodable for $element {
            fn consensus_encode<S: $crate::io::Write>(&self, mut s: S) -> Result<usize, $crate::io::Error> {
                s.write(&self.0)
            }
        }

        impl $crate::consensus::Decodable for $element {
            fn consensus_decode<D: $crate::io::Read>(mut d: D) -> Result<Self, $crate::consensus::encode::Error> {
                let mut data :[u8;$len] = [0u8; $len];
                d.read_exact(&mut data)?;
                Ok($element(data))
            }
        }
    }
}



#[rustversion::before(1.48)]
macro_rules! impl_eq_ord_hash {
    ($element:ident, $len:expr) => {

        #[rustversion::before(1.48)]
        impl core::hash::Hash for $element {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.0.to_vec().hash(state)
            }
        }


        #[rustversion::before(1.48)]
        impl core::cmp::PartialEq<$element> for $element {
            fn eq(&self, other: &$element) -> bool {
                for i in 0..$len {
                    if  self[i] != other[i] {
                        return false
                    }
                }
                true
            }
        }

        #[rustversion::before(1.48)]
        impl core::cmp::Eq for $element {}

        #[rustversion::before(1.48)]
        impl core::cmp::PartialOrd for $element {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                self.0.to_vec().partial_cmp(&other.0.to_vec())
            }
        }

        #[rustversion::before(1.48)]
        impl core::cmp::Ord for $element {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.0.to_vec().cmp(&other.0.to_vec())
            }
        }


    }
}


#[rustversion::before(1.48)]
impl_eq_ord_hash!(BLSPublicKey, 48);
#[rustversion::before(1.48)]
impl_eq_ord_hash!(BLSSignature, 96);

impl_elementencode!(BLSPublicKey, 48);
impl_elementencode!(BLSSignature, 96);
