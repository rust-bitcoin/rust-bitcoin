// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Refactored for Dash in 2022 by
//     The Dash Core Developers
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

//! Dash Outpoints.
//!
//! An outpoint is a reference to one of the indexed destinations of a transaction.
//!

#[cfg(feature = "std")] use std::error;
use core::convert::TryInto;
use core::fmt;
use io;
use hashes::Hash;
use hashes::hex::FromHex;
use consensus::{Decodable, Encodable, encode};
use Txid;

/// A reference to a transaction output.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}
serde_struct_human_string_impl!(OutPoint, "an OutPoint", txid, vout);

impl OutPoint {
    /// Creates a new [`OutPoint`].
    #[inline]
    pub fn new(txid: Txid, vout: u32) -> OutPoint {
        OutPoint { txid, vout }
    }

    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have any previous outputs.
    #[inline]
    pub fn null() -> OutPoint {
        OutPoint {
            txid: Default::default(),
            vout: u32::max_value(),
        }
    }

    /// Checks if an `OutPoint` is "null".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dashcore::blockdata::constants::genesis_block;
    /// use dashcore::network::constants::Network;
    ///
    /// let block = genesis_block(Network::Dash);
    /// let tx = &block.txdata[0];
    ///
    /// // Coinbase transactions don't have any previous output.
    /// assert!(tx.input[0].previous_output.is_null());
    /// ```
    #[inline]
    pub fn is_null(&self) -> bool {
        *self == OutPoint::null()
    }
}

impl From<[u8; 36]> for OutPoint {
    fn from(buffer: [u8; 36]) -> Self {
        let tx_id: [u8; 32] = buffer[0..32].try_into().unwrap();
        let index: [u8; 4] = buffer[32..36].try_into().unwrap();

        Self {
            txid: Txid::from_inner(tx_id),
            vout: u32::from_le_bytes(index)
        }
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        OutPoint::null()
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl Encodable for OutPoint {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let len = self.txid.consensus_encode(&mut s)?;
        Ok(len + self.vout.consensus_encode(s)?)
    }
}
impl Decodable for OutPoint {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(OutPoint {
            txid: Decodable::consensus_decode(&mut d)?,
            vout: Decodable::consensus_decode(d)?,
        })
    }
}

/// An error in parsing an OutPoint.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseOutPointError {
    /// Error in TXID part.
    Txid(hashes::hex::Error),
    /// Error in vout part.
    Vout(::core::num::ParseIntError),
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
}


impl ::core::str::FromStr for OutPoint {
    type Err = ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 75 { // 64 + 1 + 10
            return Err(ParseOutPointError::TooLong);
        }
        let find = s.find(':');
        if find == None || find != s.rfind(':') {
            return Err(ParseOutPointError::Format);
        }
        let colon = find.unwrap();
        if colon == 0 || colon == s.len() - 1 {
            return Err(ParseOutPointError::Format);
        }
        Ok(OutPoint {
            txid: Txid::from_hex(&s[..colon]).map_err(ParseOutPointError::Txid)?,
            vout: parse_vout(&s[colon+1..])?,
        })
    }
}

impl fmt::Display for ParseOutPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseOutPointError::Txid(ref e) => write!(f, "error parsing TXID: {}", e),
            ParseOutPointError::Vout(ref e) => write!(f, "error parsing vout: {}", e),
            ParseOutPointError::Format => write!(f, "OutPoint not in <txid>:<vout> format"),
            ParseOutPointError::TooLong => write!(f, "vout should be at most 10 digits"),
            ParseOutPointError::VoutNotCanonical => write!(f, "no leading zeroes or + allowed in vout part"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for ParseOutPointError {
    fn cause(&self) -> Option<&dyn  error::Error> {
        match *self {
            ParseOutPointError::Txid(ref e) => Some(e),
            ParseOutPointError::Vout(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Parses a string-encoded transaction index (vout).
/// Does not permit leading zeroes or non-digit characters.
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    s.parse().map_err(ParseOutPointError::Vout)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use Transaction;
    use super::*;

    #[test]
    fn test_outpoint() {
        assert_eq!(OutPoint::from_str("i don't care"),
                   Err(ParseOutPointError::Format));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1:1"),
                   Err(ParseOutPointError::Format));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:"),
                   Err(ParseOutPointError::Format));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:11111111111"),
                   Err(ParseOutPointError::TooLong));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:01"),
                   Err(ParseOutPointError::VoutNotCanonical));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:+42"),
                   Err(ParseOutPointError::VoutNotCanonical));
        assert_eq!(OutPoint::from_str("i don't care:1"),
                   Err(ParseOutPointError::Txid(Txid::from_hex("i don't care").unwrap_err())));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X:1"),
                   Err(ParseOutPointError::Txid(Txid::from_hex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X").unwrap_err())));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:lol"),
                   Err(ParseOutPointError::Vout(u32::from_str("lol").unwrap_err())));

        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:42"),
                   Ok(OutPoint {
                       txid: Txid::from_hex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456").unwrap(),
                       vout: 42,
                   }));
        assert_eq!(OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0"),
                   Ok(OutPoint {
                       txid: Txid::from_hex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456").unwrap(),
                       vout: 0,
                   }));
    }


    #[test]
    fn out_point_buffer() {
        let mut tx = Transaction {
            version: 0,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None
        };

        let pk_data = Vec::from_hex("b8e2d839dd21088b78bebfea3e3e632181197982").unwrap();

        let mut pk_array: [u8; 20] = [0; 20];
        for (index, kek) in pk_array.iter_mut().enumerate() {
            *kek = *pk_data.get(index).unwrap();
        }

        tx.add_burn_output(10000, &pk_array);

        let mut expected_buf = tx.txid().as_inner().to_vec();
        let mut expected_index = vec![0,0,0,0];
        // 0 serialized as 32 bits
        expected_buf.append(&mut expected_index);

        let out_point_buffer = tx.out_point_buffer(0).unwrap();

        assert_eq!(out_point_buffer.to_vec(), expected_buf);

        assert!(tx.out_point_buffer(1).is_none());
    }

    #[test]
    fn out_point_parse() {
        let mut tx = Transaction {
            version: 0,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None
        };

        let pk_data = Vec::from_hex("b8e2d839dd21088b78bebfea3e3e632181197982").unwrap();

        let mut pk_array: [u8; 20] = [0; 20];
        for (index, kek) in pk_array.iter_mut().enumerate() {
            *kek = *pk_data.get(index).unwrap();
        }

        tx.add_burn_output(10000, &pk_array);

        let mut expected_buf = tx.txid().as_inner().to_vec();
        let mut expected_index = vec![0,0,0,0];
        // 0 serialized as 32 bits
        expected_buf.append(&mut expected_index);

        let out_point_buffer = tx.out_point_buffer(0).unwrap();

        let out_point = OutPoint::from(out_point_buffer);

        assert_eq!(out_point.vout, 0);
        assert_eq!(out_point.txid, tx.txid());
    }
}