// SPDX-License-Identifier: CC0-1.0

//! Witness
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

/// Re-export everything from the [`primitives::witness`] module.
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::primitives::witness::*;

#[cfg(test)]
mod test {
    use hex::test_hex_unwrap as hex;

    use crate::sighash::EcdsaSighashType;
    use crate::Witness;

    #[test]
    fn test_push_ecdsa_sig() {
        // The very first signature in block 734,958
        let sig_bytes =
            hex!("304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b541");
        let signature = secp256k1::ecdsa::Signature::from_der(&sig_bytes).unwrap();
        let mut witness = Witness::default();
        let signature = crate::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
        witness.push_ecdsa_signature(&signature);
        let expected_witness = vec![hex!(
            "304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b54101")
            ];
        assert_eq!(witness.to_vec(), expected_witness);
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
