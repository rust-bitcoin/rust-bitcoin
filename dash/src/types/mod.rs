// use std::convert::{TryFrom, TryInto};
// use hashes::hex::FromHex;
// use consensus::encode;
// use crate::Error;
// #[cfg(feature = "serde")]
// use serde::{Serialize, Deserialize};
// #[cfg(feature = "bincode")]
// use bincode::{Encode, Decode};
//
// pub type ProTxHash = CryptoHash;
//
// pub type QuorumHash = CryptoHash;
//
// #[derive(Clone, PartialEq, Eq, Debug, Ord, PartialOrd)]
// #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
// #[cfg_attr(feature = "bincode", derive(Encode, Decode))]
// pub struct CryptoHash(pub [u8; 32]);
//
// impl TryFrom<&str> for CryptoHash {
//     type Error = Error;
//
//     fn try_from(value: &str) -> Result<Self, Self::Error> {
//         let vec = Vec::from_hex(value).map_err(|e|Error::Encode(encode::Error::Hex(e)))?;
//         let vec_len = vec.len();
//         Ok(CryptoHash(vec.try_into().map_err(|_| encode::Error::InvalidVectorSize { expected: 32, actual: vec_len })?))
//     }
// }
