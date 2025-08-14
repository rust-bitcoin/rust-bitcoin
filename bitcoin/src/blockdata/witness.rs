// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

use internals::compact_size;
use io::{BufRead, Write};

use crate::consensus::encode::{self, Error, ReadExt, WriteExt, MAX_VEC_SIZE};
use crate::consensus::{Decodable, Encodable};
use crate::crypto::ecdsa;
use crate::crypto::key::SerializedXOnlyPublicKey;
use crate::prelude::Vec;
#[cfg(doc)]
use crate::script::ScriptExt as _;
use crate::taproot::{self, ControlBlock, LeafScript, TaprootMerkleBranch, TAPROOT_ANNEX_PREFIX};
use crate::{internal_macros, Script};

type BorrowedControlBlock<'a> = ControlBlock<&'a TaprootMerkleBranch, &'a SerializedXOnlyPublicKey>;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::witness::{Iter, Witness};

impl Decodable for Witness {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let witness_elements = r.read_compact_size()? as usize;
        // Minimum size of witness element is 1 byte, so if the count is
        // greater than MAX_VEC_SIZE we must return an error.
        if witness_elements > MAX_VEC_SIZE {
            return Err(encode::ParseError::OversizedVectorAllocation {
                requested: witness_elements,
                max: MAX_VEC_SIZE,
            }
            .into());
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
                let element_size = r.read_compact_size()? as usize;
                let element_size_len = compact_size::encoded_size(element_size);
                let required_len = cursor
                    .checked_add(element_size)
                    .ok_or(encode::Error::Parse(encode::ParseError::OversizedVectorAllocation {
                        requested: usize::MAX,
                        max: MAX_VEC_SIZE,
                    }))?
                    .checked_add(element_size_len)
                    .ok_or(encode::Error::Parse(encode::ParseError::OversizedVectorAllocation {
                        requested: usize::MAX,
                        max: MAX_VEC_SIZE,
                    }))?;

                if required_len > MAX_VEC_SIZE + witness_index_space {
                    return Err(encode::ParseError::OversizedVectorAllocation {
                        requested: required_len,
                        max: MAX_VEC_SIZE,
                    }
                    .into());
                }

                // We will do content.rotate_left(witness_index_space) later.
                // Encode the position's value AFTER we rotate left.
                encode_cursor(&mut content, 0, i, cursor - witness_index_space);

                resize_if_needed(&mut content, required_len);
                cursor += (&mut content[cursor..cursor + element_size_len])
                    .emit_compact_size(element_size)?;
                r.read_exact(&mut content[cursor..cursor + element_size])?;
                cursor += element_size;
            }
            content.truncate(cursor);
            // Index space is now at the end of the Vec
            content.rotate_left(witness_index_space);
            let indices_start = cursor - witness_index_space;
            Ok(Witness::from_parts__unstable(content, witness_elements, indices_start))
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
    // `self.content` includes the varints so encoding here includes them, as expected.
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut written = w.emit_compact_size(self.len())?;

        for element in self.iter() {
            written += encode::consensus_encode_with_size(element, w)?
        }

        Ok(written)
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Witness`] type.
    pub trait WitnessExt impl for Witness {
        /// Constructs a new witness required to spend a P2WPKH output.
        ///
        /// The witness will be made up of the DER encoded signature + sighash_type followed by the
        /// serialized public key. Also useful for spending a P2SH-P2WPKH output.
        ///
        /// It is expected that `pubkey` is related to the secret key used to create `signature`.
        fn p2wpkh(signature: ecdsa::Signature, pubkey: secp256k1::PublicKey) -> Witness {
            let mut witness = Witness::new();
            witness.push(signature.serialize());
            witness.push(pubkey.serialize());
            witness
        }

        /// Constructs a new witness required to do a key path spend of a P2TR output.
        fn p2tr_key_spend(signature: &taproot::Signature) -> Witness {
            let mut witness = Witness::new();
            witness.push(signature.serialize());
            witness
        }

        /// Finishes constructing the P2TR script spend witness by pushing the required items.
        fn push_p2tr_script_spend(&mut self, script: &Script, control_block: &ControlBlock<impl AsRef<TaprootMerkleBranch>>, annex: Option<&[u8]>) {
            self.push(script.as_bytes());
            self.push(&*control_block.encode_to_arrayvec());
            if let Some(annex) = annex {
                self.push(annex);
            }
        }

        /// Pushes, as a new element on the witness, an ECDSA signature.
        ///
        /// Pushes the DER encoded signature + sighash_type, requires an allocation.
        fn push_ecdsa_signature(&mut self, signature: ecdsa::Signature) {
            self.push(signature.serialize())
        }

        /// Get Tapscript following BIP341 rules regarding accounting for an annex.
        ///
        /// This does not guarantee that this represents a P2TR [`Witness`]. It
        /// merely gets the second to last or third to last element depending on
        /// the first byte of the last element being equal to 0x50.
        ///
        /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
        fn tapscript(&self) -> Option<&Script> {
            match P2TrSpend::from_witness(self) {
                // Note: the method is named "tapscript" but historically it was actually returning
                // leaf script. This is broken but we now keep the behavior the same to not subtly
                // break someone.
                Some(P2TrSpend::Script { leaf_script, .. }) => Some(leaf_script),
                _ => None,
            }
        }

        /// Returns the leaf script with its version but without the merkle proof.
        ///
        /// This does not guarantee that this represents a P2TR [`Witness`]. It
        /// merely gets the second to last or third to last element depending on
        /// the first byte of the last element being equal to 0x50 and the associated
        /// version.
        fn taproot_leaf_script(&self) -> Option<LeafScript<&Script>> {
            match P2TrSpend::from_witness(self) {
                Some(P2TrSpend::Script { leaf_script, control_block, .. }) => {
                    Some(LeafScript { version: control_block.leaf_version, script: leaf_script, })
                },
                _ => None,
            }
        }

        /// Get the Taproot control block following BIP341 rules.
        ///
        /// This does not guarantee that this represents a P2TR [`Witness`]. It
        /// merely gets the last or second to last element depending on the first
        /// byte of the last element being equal to 0x50.
        ///
        /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
        fn taproot_control_block(&self) -> Option<BorrowedControlBlock<'_>> {
            match P2TrSpend::from_witness(self) {
                Some(P2TrSpend::Script { control_block, .. }) => Some(control_block),
                _ => None,
            }
        }

        /// Get the Taproot annex following BIP341 rules.
        ///
        /// This does not guarantee that this represents a P2TR [`Witness`].
        ///
        /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
        fn taproot_annex(&self) -> Option<&[u8]> {
            P2TrSpend::from_witness(self)?.annex()
        }

        /// Get the p2wsh witness script following BIP141 rules.
        ///
        /// This does not guarantee that this represents a P2WS [`Witness`].
        ///
        /// See [`Script::is_p2wsh`] to check whether this is actually a P2WSH witness.
        fn witness_script(&self) -> Option<&Script> { self.last().map(Script::from_bytes) }

    }
}

/// Represents a possible Taproot spend.
///
/// Taproot can be spent as key spend or script spend and, depending on which it is, different data
/// is in the witness. This type helps representing that data more cleanly when parsing the witness
/// because there are a lot of conditions that make reasoning hard. It's better to parse it at one
/// place and pass it along.
///
/// This type is so far private but it could be published eventually. The design is geared towards
/// it but it's not fully finished.
enum P2TrSpend<'a> {
    Key {
        // This field is technically present in witness in case of key spend but none of our code
        // uses it yet. Rather than deleting it, it's kept here commented as documentation and as
        // an easy way to add it if anything needs it - by just uncommenting.
        // signature: &'a [u8],
        annex: Option<&'a [u8]>,
    },
    Script {
        leaf_script: &'a Script,
        control_block: BorrowedControlBlock<'a>,
        annex: Option<&'a [u8]>,
    },
}

impl<'a> P2TrSpend<'a> {
    /// Parses `Witness` to determine what kind of Taproot spend this is.
    ///
    /// Note: this assumes `witness` is a Taproot spend. The function cannot figure it out for sure
    /// (without knowing the output), so it doesn't attempt to check anything other than what is
    /// required for the program to not crash.
    ///
    /// In other words, if the caller is certain that the witness is a valid p2tr spend (e.g.
    /// obtained from Bitcoin Core) then it's OK to unwrap this but not vice versa - `Some` does
    /// not imply correctness.
    fn from_witness(witness: &'a Witness) -> Option<Self> {
        // BIP341 says:
        //   If there are at least two witness elements, and the first byte of
        //   the last element is 0x50, this last element is called annex a
        //   and is removed from the witness stack.
        //
        // However here we're not removing anything, so we have to adjust the numbers to account
        // for the fact that annex is still there.
        match witness.len() {
            0 => None,
            1 => Some(P2TrSpend::Key {
                /* signature: witness.last().expect("len > 0") ,*/ annex: None,
            }),
            2 if witness.last().expect("len > 0").starts_with(&[TAPROOT_ANNEX_PREFIX]) => {
                let spend = P2TrSpend::Key {
                    // signature: witness.get_back(1).expect("len > 1"),
                    annex: witness.last(),
                };
                Some(spend)
            }
            // 2 => this is script spend without annex - same as when there are 3+ elements and the
            //   last one does NOT start with TAPROOT_ANNEX_PREFIX. This is handled in the catchall
            //   arm.
            3.. if witness.last().expect("len > 0").starts_with(&[TAPROOT_ANNEX_PREFIX]) => {
                let control_block = witness.get_back(1).expect("len > 1");
                let control_block = BorrowedControlBlock::decode_borrowed(control_block).ok()?;
                let spend = P2TrSpend::Script {
                    leaf_script: Script::from_bytes(witness.get_back(2).expect("len > 2")),
                    control_block,
                    annex: witness.last(),
                };
                Some(spend)
            }
            _ => {
                let control_block = witness.last().expect("len > 0");
                let control_block = BorrowedControlBlock::decode_borrowed(control_block).ok()?;
                let spend = P2TrSpend::Script {
                    leaf_script: Script::from_bytes(witness.get_back(1).expect("len > 1")),
                    control_block,
                    annex: None,
                };
                Some(spend)
            }
        }
    }

    fn annex(&self) -> Option<&'a [u8]> {
        match self {
            P2TrSpend::Key { annex, .. } => *annex,
            P2TrSpend::Script { annex, .. } => *annex,
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Witness {}
}

/// Correctness Requirements: value must always fit within u32
// This is duplicated in `primitives::witness`, if you change it please do so over there also.
#[inline]
fn encode_cursor(bytes: &mut [u8], start_of_indices: usize, index: usize, value: usize) {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    bytes[start..end]
        .copy_from_slice(&u32::to_ne_bytes(value.try_into().expect("larger than u32")));
}

#[cfg(test)]
mod test {
    use hex_lit::hex;

    use super::*;
    use crate::consensus::{deserialize, encode, serialize};
    use crate::hex::DisplayHex;
    use crate::sighash::EcdsaSighashType;
    use crate::taproot::LeafVersion;
    use crate::Transaction;

    #[test]
    fn exact_sized_iterator() {
        let mut witness = Witness::default();
        for i in 0..5 {
            assert_eq!(witness.iter().len(), i);
            witness.push([0u8]);
        }
        let mut iter = witness.iter();
        for i in (0..=5).rev() {
            assert_eq!(iter.len(), i);
            iter.next();
        }
    }

    #[test]
    fn push_ecdsa_sig() {
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
    fn consensus_serialize() {
        let el_0 =
            hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105").to_vec();
        let el_1 = hex!("000000").to_vec();

        let mut want_witness = Witness::default();
        want_witness.push(&el_0);
        want_witness.push(&el_1);

        let vec = vec![el_0, el_1];

        // Puts a CompactSize at the front as well as one at the front of each element.
        let want_ser: Vec<u8> = encode::serialize(&vec);

        // `from_slice` expects bytes slices _without_ leading `CompactSize`.
        let got_witness = Witness::from_slice(&vec);
        assert_eq!(got_witness, want_witness);

        let got_ser = encode::serialize(&got_witness);
        assert_eq!(got_ser, want_ser);

        let rinsed: Witness = encode::deserialize(&got_ser).unwrap();
        assert_eq!(rinsed, want_witness)
    }

    #[test]
    fn get_tapscript() {
        let tapscript = hex!("deadbeef");
        let control_block =
            hex!("c0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness = Witness::from([tapscript.as_slice(), &control_block]);
        let witness_annex = Witness::from([tapscript.as_slice(), &control_block, &annex]);

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.tapscript(), Some(Script::from_bytes(&tapscript[..])));
        assert_eq!(witness_annex.tapscript(), Some(Script::from_bytes(&tapscript[..])));
    }

    #[test]
    fn get_taproot_leaf_script() {
        let tapscript = hex!("deadbeef");
        let control_block =
            hex!("c0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness = Witness::from([tapscript.as_slice(), &control_block]);
        let witness_annex = Witness::from([tapscript.as_slice(), &control_block, &annex]);

        let expected_leaf_script =
            LeafScript { version: LeafVersion::TapScript, script: Script::from_bytes(&tapscript) };

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_leaf_script().unwrap(), expected_leaf_script);
        assert_eq!(witness_annex.taproot_leaf_script().unwrap(), expected_leaf_script);
    }

    #[test]
    fn get_tapscript_from_keypath() {
        let signature = hex!("deadbeef");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness = Witness::from([signature]);
        let witness_annex = Witness::from([signature.as_slice(), &annex]);

        // With or without annex, no tapscript should be returned.
        assert_eq!(witness.tapscript(), None);
        assert_eq!(witness_annex.tapscript(), None);
    }

    #[test]
    fn get_control_block() {
        let tapscript = hex!("deadbeef");
        let control_block =
            hex!("c0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let expected_control_block = BorrowedControlBlock::decode_borrowed(&control_block).unwrap();
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");
        let signature = vec![0xff; 64];

        let witness = Witness::from([tapscript.as_slice(), &control_block]);
        let witness_annex = Witness::from([tapscript.as_slice(), &control_block, &annex]);
        let witness_key_spend_annex = Witness::from([signature.as_slice(), &annex]);

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_control_block().unwrap(), expected_control_block);
        assert_eq!(witness_annex.taproot_control_block().unwrap(), expected_control_block);
        assert!(witness_key_spend_annex.taproot_control_block().is_none())
    }

    #[test]
    fn get_annex() {
        let tapscript = hex!("deadbeef");
        let control_block =
            hex!("c0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness = Witness::from([tapscript.as_slice(), &control_block]);
        let witness_annex = Witness::from([tapscript.as_slice(), &control_block, &annex]);

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_annex(), None);
        assert_eq!(witness_annex.taproot_annex(), Some(&annex[..]));

        // Now for keyspend
        let signature = hex!("deadbeef");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness = Witness::from([signature]);
        let witness_annex = Witness::from([signature.as_slice(), &annex]);

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_annex(), None);
        assert_eq!(witness_annex.taproot_annex(), Some(&annex[..]));
    }

    #[test]
    fn tx() {
        const S: &str = "02000000000102b44f26b275b8ad7b81146ba3dbecd081f9c1ea0dc05b97516f56045cfcd3df030100000000ffffffff1cb4749ae827c0b75f3d0a31e63efc8c71b47b5e3634a4c698cd53661cab09170100000000ffffffff020b3a0500000000001976a9143ea74de92762212c96f4dd66c4d72a4deb20b75788ac630500000000000016001493a8dfd1f0b6a600ab01df52b138cda0b82bb7080248304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c0121026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e950247304402203ef00489a0d549114977df2820fab02df75bebb374f5eee9e615107121658cfa02204751f2d1784f8e841bff6d3bcf2396af2f1a5537c0e4397224873fbd3bfbe9cf012102ae6aa498ce2dd204e9180e71b4fb1260fe3d1a95c8025b34e56a9adf5f278af200000000";
        let tx_bytes = hex!(S);
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let expected_wit = ["304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c01", "026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e95"];
        for (i, wit_el) in tx.inputs[0].witness.iter().enumerate() {
            assert_eq!(expected_wit[i], wit_el.to_lower_hex_string());
        }
        assert_eq!(expected_wit[1], tx.inputs[0].witness.last().unwrap().to_lower_hex_string());
        assert_eq!(
            expected_wit[0],
            tx.inputs[0].witness.get_back(1).unwrap().to_lower_hex_string()
        );
        assert_eq!(expected_wit[0], tx.inputs[0].witness.get(0).unwrap().to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.inputs[0].witness.get(1).unwrap().to_lower_hex_string());
        assert_eq!(None, tx.inputs[0].witness.get(2));
        assert_eq!(expected_wit[0], tx.inputs[0].witness[0].to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.inputs[0].witness[1].to_lower_hex_string());

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
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::{Witness, WitnessExt};

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
