// SPDX-License-Identifier: CC0-1.0

//! Witness
//!
//! This module contains the [`Witness`] struct and related methods to operate on it
//!

use secp256k1::ecdsa;

use crate::blockdata::transaction::EcdsaSighashType;
use crate::consensus::encode::{Error, MAX_VEC_SIZE};
use crate::consensus::{Decodable, Encodable, WriteExt};
use crate::io::{self, Read, Write};
use crate::prelude::*;
use crate::VarInt;

/// The Witness is the data used to unlock bitcoins since the [segwit upgrade](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
///
/// Can be logically seen as an array of byte-arrays `Vec<Vec<u8>>` and indeed you can convert from
/// it [`Witness::from_vec`] and convert into it [`Witness::to_vec`].
///
/// For serialization and deserialization performance it is stored internally as a single `Vec`,
/// saving some allocations.
///
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Witness {
    /// contains the witness Vec<Vec<u8>> serialization without the initial varint indicating the
    /// number of elements (which is stored in `witness_elements`)
    content: Vec<u8>,

    /// Number of elements in the witness.
    /// It is stored separately (instead of as VarInt in the initial part of content) so that method
    /// like [`Witness::push`] doesn't have case requiring to shift the entire array
    witness_elements: usize,

    /// If `witness_elements > 0` it's a valid index pointing to the last witness element in `content`
    /// (Including the varint specifying the length of the element)
    last: usize,

    /// If `witness_elements > 1` it's a valid index pointing to the second-to-last witness element in `content`
    /// (Including the varint specifying the length of the element)
    second_to_last: usize,
}

/// Support structure to allow efficient and convenient iteration over the Witness elements
pub struct Iter<'a> {
    inner: core::slice::Iter<'a, u8>,
    remaining: usize,
}

impl Decodable for Witness {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let witness_elements = VarInt::consensus_decode(r)?.0 as usize;
        if witness_elements == 0 {
            Ok(Witness::default())
        } else {
            let mut cursor = 0usize;
            let mut last = 0usize;
            let mut second_to_last = 0usize;

            // this number should be determined as high enough to cover most witness, and low enough
            // to avoid wasting space without reallocating
            let mut content = vec![0u8; 128];

            for _ in 0..witness_elements {
                second_to_last = last;
                last = cursor;
                let element_size_varint = VarInt::consensus_decode(r)?;
                let element_size_varint_len = element_size_varint.len();
                let element_size = element_size_varint.0 as usize;
                let required_len = cursor
                    .checked_add(element_size)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::max_value(),
                        max: MAX_VEC_SIZE,
                    })?
                    .checked_add(element_size_varint_len)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::max_value(),
                        max: MAX_VEC_SIZE,
                    })?;

                if required_len > MAX_VEC_SIZE {
                    return Err(self::Error::OversizedVectorAllocation {
                        requested: required_len,
                        max: MAX_VEC_SIZE,
                    });
                }

                resize_if_needed(&mut content, required_len);
                element_size_varint
                    .consensus_encode(&mut &mut content[cursor..cursor + element_size_varint_len])?;
                cursor += element_size_varint_len;
                r.read_exact(&mut content[cursor..cursor + element_size])?;
                cursor += element_size;
            }
            content.truncate(cursor);
            Ok(Witness {
                content,
                witness_elements,
                last,
                second_to_last,
            })
        }
    }
}

fn resize_if_needed(vec: &mut Vec<u8>, required_len: usize) {
    if required_len >= vec.len() {
        let mut new_len = vec.len().max(1);
        while new_len <= required_len {
            new_len *= 2;
        }
        vec.resize(new_len, 0);
    }
}

impl Encodable for Witness {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = VarInt(self.witness_elements as u64);
        len.consensus_encode(w)?;
        w.emit_slice(&self.content[..])?;
        Ok(self.content.len() + len.len())
    }
}

impl Witness {
    /// Create a new empty [`Witness`]
    pub fn new() -> Self {
        Witness::default()
    }

    /// Creates [`Witness`] object from an array of byte-arrays
    pub fn from_vec(vec: Vec<Vec<u8>>) -> Self {
        let witness_elements = vec.len();

        let content_size: usize = vec
            .iter()
            .map(|el| el.len() + VarInt(el.len() as u64).len())
            .sum();
        let mut content = vec![0u8; content_size];
        let mut cursor = 0usize;
        let mut last = 0;
        let mut second_to_last = 0;
        for el in vec {
            second_to_last = last;
            last = cursor;
            let el_len_varint = VarInt(el.len() as u64);
            el_len_varint
                .consensus_encode(&mut &mut content[cursor..cursor + el_len_varint.len()])
                .expect("writers on vec don't errors, space granted by content_size");
            cursor += el_len_varint.len();
            content[cursor..cursor + el.len()].copy_from_slice(&el);
            cursor += el.len();
        }

        Witness {
            witness_elements,
            content,
            last,
            second_to_last,
        }
    }

    /// Convenience method to create an array of byte-arrays from this witness
    pub fn to_vec(&self) -> Vec<Vec<u8>> {
        self.iter().map(|s| s.to_vec()).collect()
    }

    /// Returns `true` if the witness contains no element
    pub fn is_empty(&self) -> bool {
        self.witness_elements == 0
    }

    /// Returns a struct implementing [`Iterator`]
    pub fn iter(&self) -> Iter {
        Iter { inner: self.content.iter(), remaining: self.witness_elements }
    }

    /// Returns the number of elements this witness holds
    pub fn len(&self) -> usize {
        self.witness_elements as usize
    }

    /// Returns the bytes required when this Witness is consensus encoded
    pub fn serialized_len(&self) -> usize {
        self.iter()
            .map(|el| VarInt(el.len() as u64).len() + el.len())
            .sum::<usize>()
            + VarInt(self.witness_elements as u64).len()
    }

    /// Clear the witness
    pub fn clear(&mut self) {
        self.content.clear();
        self.witness_elements = 0;
        self.last = 0;
        self.second_to_last = 0;
    }

    /// Push a new element on the witness, requires an allocation
    pub fn push<T: AsRef<[u8]>>(&mut self, new_element: T) {
        let new_element = new_element.as_ref();
        self.witness_elements += 1;
        self.second_to_last = self.last;
        self.last = self.content.len();
        let element_len_varint = VarInt(new_element.len() as u64);
        let current_content_len = self.content.len();
        self.content
            .resize(current_content_len + element_len_varint.len() + new_element.len(), 0);
        let end_varint = current_content_len + element_len_varint.len();
        element_len_varint
            .consensus_encode(&mut &mut self.content[current_content_len..end_varint])
            .expect("writers on vec don't error, space granted through previous resize");
        self.content[end_varint..].copy_from_slice(new_element);
    }

    /// Pushes a DER-encoded ECDSA signature with a signature hash type as a new element on the
    /// witness, requires an allocation.
    pub fn push_bitcoin_signature(&mut self, signature: &ecdsa::SerializedSignature, hash_type: EcdsaSighashType) {
        // Note that a maximal length ECDSA signature is 72 bytes, plus the sighash type makes 73
        let mut sig = [0; 73];
        sig[..signature.len()].copy_from_slice(signature);
        sig[signature.len()] = hash_type as u8;
        self.push(&sig[..signature.len() + 1]);
    }


    fn element_at(&self, index: usize) -> Option<&[u8]> {
        let varint = VarInt::consensus_decode(&mut &self.content[index..]).ok()?;
        let start = index + varint.len();
        Some(&self.content[start..start + varint.0 as usize])
    }

    /// Return the last element in the witness, if any
    pub fn last(&self) -> Option<&[u8]> {
        if self.witness_elements == 0 {
            None
        } else {
            self.element_at(self.last)
        }
    }

    /// Return the second-to-last element in the witness, if any
    pub fn second_to_last(&self) -> Option<&[u8]> {
        if self.witness_elements <= 1 {
            None
        } else {
            self.element_at(self.second_to_last)
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let varint = VarInt::consensus_decode(&mut self.inner.as_slice()).ok()?;
        self.inner.nth(varint.len() - 1)?; // VarInt::len returns at least 1
        let len = varint.0 as usize;
        let slice = &self.inner.as_slice()[..len];
        if len > 0 {
            // we don't need to advance if the element is empty
            self.inner.nth(len - 1)?;
        }
        self.remaining -= 1;
        Some(slice)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {}

// Serde keep backward compatibility with old Vec<Vec<u8>> format
#[cfg(feature = "serde")]
impl serde::Serialize for Witness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use crate::hashes::hex::ToHex;
        use serde::ser::SerializeSeq;

        let human_readable = serializer.is_human_readable();
        let mut seq = serializer.serialize_seq(Some(self.witness_elements))?;

        for elem in self.iter() {
            if human_readable {
                seq.serialize_element(&elem.to_hex())?;
            } else {
                seq.serialize_element(&elem)?;
            }
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Witness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;         // Human-readable visitor.
        impl<'de> serde::de::Visitor<'de> for Visitor
        {
            type Value = Witness;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "a sequence of hex arrays")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error>
            {
                use crate::hashes::hex::FromHex;
                use crate::hashes::hex::Error::*;
                use serde::de::{self, Unexpected};

                let mut ret = match a.size_hint() {
                    Some(len) => Vec::with_capacity(len),
                    None => Vec::new(),
                };

                while let Some(elem) = a.next_element::<String>()? {
                    let vec = Vec::<u8>::from_hex(&elem).map_err(|e| {
                        match e {
                            InvalidChar(b) => {
                                match core::char::from_u32(b.into()) {
                                    Some(c) => de::Error::invalid_value(Unexpected::Char(c), &"a valid hex character"),
                                    None => de::Error::invalid_value(Unexpected::Unsigned(b.into()), &"a valid hex character")
                                }
                            }
                            OddLengthString(len) => de::Error::invalid_length(len, &"an even length string"),
                            InvalidLength(expected, got) => {
                                let exp = format!("expected length: {}", expected);
                                de::Error::invalid_length(got, &exp.as_str())
                            }
                        }
                    })?;
                    ret.push(vec);
                }
                Ok(Witness::from_vec(ret))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_seq(Visitor)
        } else {
            let vec: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
            Ok(Witness::from_vec(vec))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::consensus::{deserialize, serialize};
    use crate::hashes::hex::{FromHex, ToHex};
    use crate::Transaction;
    use crate::secp256k1::ecdsa;

    #[test]
    fn test_push() {
        let mut witness = Witness::default();
        assert_eq!(witness.last(), None);
        assert_eq!(witness.second_to_last(), None);
        witness.push(&vec![0u8]);
        let expected = Witness {
            witness_elements: 1,
            content: vec![1u8, 0],
            last: 0,
            second_to_last: 0,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[0u8][..]));
        assert_eq!(witness.second_to_last(), None);
        witness.push(&vec![2u8, 3u8]);
        let expected = Witness {
            witness_elements: 2,
            content: vec![1u8, 0, 2, 2, 3],
            last: 2,
            second_to_last: 0,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.second_to_last(), Some(&[0u8][..]));
    }


    #[test]
    fn test_iter_len() {
        let mut witness = Witness::default();
        for i in 0..5 {
            assert_eq!(witness.iter().len(), i);
            witness.push(&vec![0u8]);
        }
        let mut iter = witness.iter();
        for i in (0..=5).rev() {
            assert_eq!(iter.len(), i);
            iter.next();
        }
    }

    #[test]
    fn test_push_ecdsa_sig() {
        // The very first signature in block 734,958
        let sig_bytes =
            Vec::from_hex("304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b541");
        let sig = ecdsa::Signature::from_der(&sig_bytes.unwrap()).unwrap();
        let mut witness = Witness::default();
        witness.push_bitcoin_signature(&sig.serialize_der(), EcdsaSighashType::All);
        let expected_witness = vec![Vec::from_hex(
            "304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b54101")
            .unwrap()];
        assert_eq!(witness.to_vec(), expected_witness);
    }

    #[test]
    fn test_witness() {
        let w0 =
            Vec::from_hex("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105")
                .unwrap();
        let w1 = Vec::from_hex("000000").unwrap();
        let witness_vec = vec![w0.clone(), w1.clone()];
        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness = Witness {
            content: witness_serialized[1..].to_vec(),
            witness_elements: 2,
            last: 34,
            second_to_last: 0,
        };
        for (i, el) in witness.iter().enumerate() {
            assert_eq!(witness_vec[i], el);
        }
        assert_eq!(witness.last(), Some(&w1[..]));
        assert_eq!(witness.second_to_last(), Some(&w0[..]));

        let w_into = Witness::from_vec(witness_vec);
        assert_eq!(w_into, witness);

        assert_eq!(witness_serialized, serialize(&witness));
    }

    #[test]
    fn test_tx() {
        let s = "02000000000102b44f26b275b8ad7b81146ba3dbecd081f9c1ea0dc05b97516f56045cfcd3df030100000000ffffffff1cb4749ae827c0b75f3d0a31e63efc8c71b47b5e3634a4c698cd53661cab09170100000000ffffffff020b3a0500000000001976a9143ea74de92762212c96f4dd66c4d72a4deb20b75788ac630500000000000016001493a8dfd1f0b6a600ab01df52b138cda0b82bb7080248304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c0121026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e950247304402203ef00489a0d549114977df2820fab02df75bebb374f5eee9e615107121658cfa02204751f2d1784f8e841bff6d3bcf2396af2f1a5537c0e4397224873fbd3bfbe9cf012102ae6aa498ce2dd204e9180e71b4fb1260fe3d1a95c8025b34e56a9adf5f278af200000000";
        let tx_bytes = Vec::from_hex(s).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let expected_wit = ["304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c01", "026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e95"];
        for (i, wit_el) in tx.input[0].witness.iter().enumerate() {
            assert_eq!(expected_wit[i], wit_el.to_hex());
        }
        assert_eq!(expected_wit[1], tx.input[0].witness.last().unwrap().to_hex());
        assert_eq!(expected_wit[0], tx.input[0].witness.second_to_last().unwrap().to_hex());

        let tx_bytes_back = serialize(&tx);
        assert_eq!(tx_bytes_back, tx_bytes);
    }

    #[test]
    fn fuzz_cases() {
        let s = "26ff0000000000c94ce592cf7a4cbb68eb00ce374300000057cd0000000000000026";
        let bytes = Vec::from_hex(s).unwrap();
        assert!(deserialize::<Witness>(&bytes).is_err()); // OversizedVectorAllocation

        let s = "24000000ffffffffffffffffffffffff";
        let bytes = Vec::from_hex(s).unwrap();
        assert!(deserialize::<Witness>(&bytes).is_err()); // OversizedVectorAllocation
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_bincode() {
        use bincode;

        let old_witness_format = vec![vec![0u8], vec![2]];
        let new_witness_format = Witness::from_vec(old_witness_format.clone());

        let old = bincode::serialize(&old_witness_format).unwrap();
        let new = bincode::serialize(&new_witness_format).unwrap();

        assert_eq!(old, new);

        let back: Witness = bincode::deserialize(&new).unwrap();
        assert_eq!(new_witness_format, back);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_human() {
        use serde_json;

        let witness = Witness::from_vec(vec![vec![0u8, 123, 75], vec![2u8, 6, 3, 7, 8]]);

        let json = serde_json::to_string(&witness).unwrap();

        assert_eq!(json, r#"["007b4b","0206030708"]"#);

        let back: Witness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, back);
    }
}


#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};
    use super::Witness;

    #[bench]
    pub fn bench_big_witness_to_vec(bh: &mut Bencher) {
        let raw_witness = vec![vec![1u8]; 5];
        let witness = Witness::from_vec(raw_witness);

        bh.iter(|| {
            black_box(witness.to_vec());
        });
    }

    #[bench]
    pub fn bench_witness_to_vec(bh: &mut Bencher) {
        let raw_witness = vec![vec![1u8]; 3];
        let witness = Witness::from_vec(raw_witness);

        bh.iter(|| {
            black_box(witness.to_vec());
        });
    }

}
