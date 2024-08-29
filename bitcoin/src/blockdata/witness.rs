// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

use internals::cursor;
use io::{BufRead, Write};

use crate::consensus::encode::{Error, MAX_VEC_SIZE};
use crate::consensus::{Decodable, Encodable, WriteExt};
use crate::crypto::ecdsa;
use crate::prelude::Vec;
#[cfg(doc)]
use crate::script::ScriptExt as _;
use crate::taproot::{self, TAPROOT_ANNEX_PREFIX};
use crate::{Script, VarInt};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::witness::{Witness, Iter};

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Witness`] type.
    pub trait WitnessExt impl for Witness {
        /// Creates a witness required to spend a P2WPKH output.
        ///
        /// The witness will be made up of the DER encoded signature + sighash_type followed by the
        /// serialized public key. Also useful for spending a P2SH-P2WPKH output.
        ///
        /// It is expected that `pubkey` is related to the secret key used to create `signature`.
        fn p2wpkh(signature: ecdsa::Signature, pubkey: secp256k1::PublicKey) -> Witness {
            let mut witness = Witness::new();
            witness.__push_slice(&signature.serialize());
            witness.__push_slice(&pubkey.serialize());
            witness
        }

        /// Creates a witness required to do a key path spend of a P2TR output.
        fn p2tr_key_spend(signature: &taproot::Signature) -> Witness {
            let mut witness = Witness::new();
            witness.__push_slice(&signature.serialize());
            witness
        }

        /// Push a new element on the witness, requires an allocation.
        fn push<T: AsRef<[u8]>>(&mut self, new_element: T) {
            self.__push_slice(new_element.as_ref());
        }

        /// Pushes, as a new element on the witness, an ECDSA signature.
        ///
        /// Pushes the DER encoded signature + sighash_type, requires an allocation.
        fn push_ecdsa_signature(&mut self, signature: ecdsa::Signature) {
            self.__push_slice(&signature.serialize())
        }

        /// Get Tapscript following BIP341 rules regarding accounting for an annex.
        ///
        /// This does not guarantee that this represents a P2TR [`Witness`]. It
        /// merely gets the second to last or third to last element depending on
        /// the first byte of the last element being equal to 0x50.
        ///
        /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
        fn tapscript(&self) -> Option<&Script> {
            self.last().and_then(|last| {
                // From BIP341:
                // If there are at least two witness elements, and the first byte of
                // the last element is 0x50, this last element is called annex a
                // and is removed from the witness stack.
                if self.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                    self.nth(self.len() - 3).map(Script::from_bytes)
                } else if self.len() >= 2 {
                    self.nth(self.len() - 2).map(Script::from_bytes)
                } else {
                    None
                }
            })
        }

        /// Get the taproot control block following BIP341 rules.
        ///
        /// This does not guarantee that this represents a P2TR [`Witness`]. It
        /// merely gets the last or second to last element depending on the first
        /// byte of the last element being equal to 0x50.
        ///
        /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
        fn taproot_control_block(&self) -> Option<&[u8]> {
            self.last().and_then(|last| {
                // From BIP341:
                // If there are at least two witness elements, and the first byte of
                // the last element is 0x50, this last element is called annex a
                // and is removed from the witness stack.
                if self.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                    self.nth(self.len() - 2)
                } else if self.len() >= 2 {
                    Some(last)
                } else {
                    None
                }
            })
        }

        /// Get the taproot annex following BIP341 rules.
        ///
        /// This does not guarantee that this represents a P2TR [`Witness`].
        ///
        /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
        fn taproot_annex(&self) -> Option<&[u8]> {
            self.last().and_then(|last| {
                // From BIP341:
                // If there are at least two witness elements, and the first byte of
                // the last element is 0x50, this last element is called annex a
                // and is removed from the witness stack.
                if self.len() >= 2 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                    Some(last)
                } else {
                    None
                }
            })
        }

        /// Get the p2wsh witness script following BIP141 rules.
        ///
        /// This does not guarantee that this represents a P2WS [`Witness`].
        ///
        /// See [`Script::is_p2wsh`] to check whether this is actually a P2WSH witness.
        fn witness_script(&self) -> Option<&Script> { self.last().map(Script::from_bytes) }
    }
}

impl Decodable for Witness {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let witness_elements = VarInt::consensus_decode(r)?.0 as usize;
        // Minimum size of witness element is 1 byte, so if the count is
        // greater than MAX_VEC_SIZE we must return an error.
        if witness_elements > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation {
                requested: witness_elements,
                max: MAX_VEC_SIZE,
            });
        }
        if witness_elements == 0 {
            Ok(Witness::default())
        } else {
            // Leave space at the head for element positions.
            // We will rotate them to the end of the Vec later.
            let witness_index_space = witness_elements * 4;
            let mut cursor = witness_index_space;

            // this number should be determined as high enough to cover most witness, and low enough
            // to avoid wasting space without reallocating
            let mut content = vec![0u8; cursor + 128];

            for i in 0..witness_elements {
                let element_size_varint = VarInt::consensus_decode(r)?;
                let element_size_varint_len = element_size_varint.size();
                let element_size = element_size_varint.0 as usize;
                let required_len = cursor
                    .checked_add(element_size)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::MAX,
                        max: MAX_VEC_SIZE,
                    })?
                    .checked_add(element_size_varint_len)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::MAX,
                        max: MAX_VEC_SIZE,
                    })?;

                if required_len > MAX_VEC_SIZE + witness_index_space {
                    return Err(self::Error::OversizedVectorAllocation {
                        requested: required_len,
                        max: MAX_VEC_SIZE,
                    });
                }

                // We will do content.rotate_left(witness_index_space) later.
                // Encode the position's value AFTER we rotate left.
                cursor::encode(&mut content, 0, i, cursor - witness_index_space);

                resize_if_needed(&mut content, required_len);
                element_size_varint.consensus_encode(
                    &mut &mut content[cursor..cursor + element_size_varint_len],
                )?;
                cursor += element_size_varint_len;
                r.read_exact(&mut content[cursor..cursor + element_size])?;
                cursor += element_size;
            }
            content.truncate(cursor);
            // Index space is now at the end of the Vec
            content.rotate_left(witness_index_space);
            Ok(Witness::__from_parts(content, witness_elements, cursor - witness_index_space))
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
        let len = VarInt::from(self.len());
        len.consensus_encode(w)?;
        let bytes = self.__raw_bytes_excluding_compact_size();
        w.emit_slice(bytes)?;
        Ok(bytes.len() + len.size())
    }
}

#[cfg(test)]
mod test {
    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::consensus::{deserialize, serialize};
    use crate::hex::DisplayHex;
    use crate::sighash::EcdsaSighashType;
    use crate::Transaction;

    fn append_u32_vec(mut v: Vec<u8>, n: &[u32]) -> Vec<u8> {
        for &num in n {
            v.extend_from_slice(&num.to_ne_bytes());
        }
        v
    }

    macro_rules! witness {
        (witness_elements: $witness_elements:expr, content: $content:expr, indices_start: $indices_start:expr,) => {
            Witness::__from_parts($content, $witness_elements, $indices_start)
        }
    }

    #[test]
    fn witness_debug_can_display_empty_instruction() {
        let witness = witness! {
            witness_elements: 1,
            content: append_u32_vec(vec![], &[0]),
            indices_start: 2,
        };
        println!("{:?}", witness);
    }

    #[test]
    fn test_push() {
        let mut witness = Witness::default();
        assert_eq!(witness.last(), None);
        assert_eq!(witness.second_to_last(), None);
        assert_eq!(witness.nth(0), None);
        assert_eq!(witness.nth(1), None);
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);
        witness.push(&vec![0u8]);
        let expected = witness! {
            witness_elements: 1,
            content: append_u32_vec(vec![1u8, 0], &[0]),
            indices_start: 2,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[0u8][..]));
        assert_eq!(witness.second_to_last(), None);
        assert_eq!(witness.nth(0), Some(&[0u8][..]));
        assert_eq!(witness.nth(1), None);
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);
        assert_eq!(&witness[0], &[0u8][..]);
        witness.push(&vec![2u8, 3u8]);
        let expected = witness! {
            witness_elements: 2,
            content: append_u32_vec(vec![1u8, 0, 2, 2, 3], &[0, 2]),
            indices_start: 5,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.second_to_last(), Some(&[0u8][..]));
        assert_eq!(witness.nth(0), Some(&[0u8][..]));
        assert_eq!(witness.nth(1), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);
        assert_eq!(&witness[0], &[0u8][..]);
        assert_eq!(&witness[1], &[2u8, 3u8][..]);
        witness.push(&vec![4u8, 5u8]);
        let expected = witness! {
            witness_elements: 3,
            content: append_u32_vec(vec![1u8, 0, 2, 2, 3, 2, 4, 5], &[0, 2, 5]),
            indices_start: 8,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[4u8, 5u8][..]));
        assert_eq!(witness.second_to_last(), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.nth(0), Some(&[0u8][..]));
        assert_eq!(witness.nth(1), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.nth(2), Some(&[4u8, 5u8][..]));
        assert_eq!(witness.nth(3), None);
        assert_eq!(&witness[0], &[0u8][..]);
        assert_eq!(&witness[1], &[2u8, 3u8][..]);
        assert_eq!(&witness[2], &[4u8, 5u8][..]);
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
            hex!("304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b541");
        let signature = secp256k1::ecdsa::Signature::from_der(&sig_bytes).unwrap();
        let mut witness = Witness::default();
        let signature = crate::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
        witness.push_ecdsa_signature(signature);
        let expected_witness = vec![hex!(
            "304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b54101")
            ];
        assert_eq!(witness.to_vec(), expected_witness);
    }

    #[test]
    fn test_witness() {
        let w0 = hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105");
        let w1 = hex!("000000");
        let witness_vec = vec![w0.clone(), w1.clone()];
        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness = witness! {
            witness_elements: 2,
            content: append_u32_vec(witness_serialized[1..].to_vec(), &[0, 34]),
            indices_start: 38,
        };
        for (i, el) in witness.iter().enumerate() {
            assert_eq!(witness_vec[i], el);
        }
        assert_eq!(witness.last(), Some(&w1[..]));
        assert_eq!(witness.second_to_last(), Some(&w0[..]));
        assert_eq!(witness.nth(0), Some(&w0[..]));
        assert_eq!(witness.nth(1), Some(&w1[..]));
        assert_eq!(witness.nth(2), None);
        assert_eq!(&witness[0], &w0[..]);
        assert_eq!(&witness[1], &w1[..]);

        let w_into = Witness::from_slice(&witness_vec);
        assert_eq!(w_into, witness);

        assert_eq!(witness_serialized, serialize(&witness));
    }

    #[test]
    fn test_get_tapscript() {
        let tapscript = hex!("deadbeef");
        let control_block = hex!("02");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![tapscript.clone(), control_block.clone()];
        let witness_vec_annex = vec![tapscript.clone(), control_block, annex];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.tapscript(), Some(Script::from_bytes(&tapscript[..])));
        assert_eq!(witness_annex.tapscript(), Some(Script::from_bytes(&tapscript[..])));
    }

    #[test]
    fn test_get_control_block() {
        let tapscript = hex!("deadbeef");
        let control_block = hex!("02");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![tapscript.clone(), control_block.clone()];
        let witness_vec_annex = vec![tapscript.clone(), control_block.clone(), annex];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_control_block(), Some(&control_block[..]));
        assert_eq!(witness_annex.taproot_control_block(), Some(&control_block[..]));
    }

    #[test]
    fn test_get_annex() {
        let tapscript = hex!("deadbeef");
        let control_block = hex!("02");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![tapscript.clone(), control_block.clone()];
        let witness_vec_annex = vec![tapscript.clone(), control_block.clone(), annex.clone()];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_annex(), None);
        assert_eq!(witness_annex.taproot_annex(), Some(&annex[..]));

        // Now for keyspend
        let signature = hex!("deadbeef");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![signature.clone()];
        let witness_vec_annex = vec![signature.clone(), annex.clone()];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_annex(), None);
        assert_eq!(witness_annex.taproot_annex(), Some(&annex[..]));
    }

    #[test]
    fn test_tx() {
        const S: &str = "02000000000102b44f26b275b8ad7b81146ba3dbecd081f9c1ea0dc05b97516f56045cfcd3df030100000000ffffffff1cb4749ae827c0b75f3d0a31e63efc8c71b47b5e3634a4c698cd53661cab09170100000000ffffffff020b3a0500000000001976a9143ea74de92762212c96f4dd66c4d72a4deb20b75788ac630500000000000016001493a8dfd1f0b6a600ab01df52b138cda0b82bb7080248304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c0121026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e950247304402203ef00489a0d549114977df2820fab02df75bebb374f5eee9e615107121658cfa02204751f2d1784f8e841bff6d3bcf2396af2f1a5537c0e4397224873fbd3bfbe9cf012102ae6aa498ce2dd204e9180e71b4fb1260fe3d1a95c8025b34e56a9adf5f278af200000000";
        let tx_bytes = hex!(S);
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let expected_wit = ["304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c01", "026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e95"];
        for (i, wit_el) in tx.input[0].witness.iter().enumerate() {
            assert_eq!(expected_wit[i], wit_el.to_lower_hex_string());
        }
        assert_eq!(expected_wit[1], tx.input[0].witness.last().unwrap().to_lower_hex_string());
        assert_eq!(
            expected_wit[0],
            tx.input[0].witness.second_to_last().unwrap().to_lower_hex_string()
        );
        assert_eq!(expected_wit[0], tx.input[0].witness.nth(0).unwrap().to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.input[0].witness.nth(1).unwrap().to_lower_hex_string());
        assert_eq!(None, tx.input[0].witness.nth(2));
        assert_eq!(expected_wit[0], tx.input[0].witness[0].to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.input[0].witness[1].to_lower_hex_string());

        let tx_bytes_back = serialize(&tx);
        assert_eq!(tx_bytes_back, tx_bytes);
    }

    #[test]
    fn fuzz_cases() {
        let bytes = hex!("26ff0000000000c94ce592cf7a4cbb68eb00ce374300000057cd0000000000000026");
        assert!(deserialize::<Witness>(&bytes).is_err()); // OversizedVectorAllocation

        let bytes = hex!("24000000ffffffffffffffffffffffff");
        assert!(deserialize::<Witness>(&bytes).is_err()); // OversizedVectorAllocation
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_bincode() {
        use bincode;

        let old_witness_format = vec![vec![0u8], vec![2]];
        let new_witness_format = Witness::from_slice(&old_witness_format);

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

        let witness = Witness::from_slice(&[vec![0u8, 123, 75], vec![2u8, 6, 3, 7, 8]]);

        let json = serde_json::to_string(&witness).unwrap();

        assert_eq!(json, r#"["007b4b","0206030708"]"#);

        let back: Witness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, back);
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::Witness;

    #[bench]
    pub fn bench_big_witness_to_vec(bh: &mut Bencher) {
        let raw_witness = [[1u8]; 5];
        let witness = Witness::from_slice(&raw_witness);

        bh.iter(|| {
            black_box(witness.to_vec());
        });
    }

    #[bench]
    pub fn bench_witness_to_vec(bh: &mut Bencher) {
        let raw_witness = vec![vec![1u8]; 3];
        let witness = Witness::from_slice(&raw_witness);

        bh.iter(|| {
            black_box(witness.to_vec());
        });
    }
}
