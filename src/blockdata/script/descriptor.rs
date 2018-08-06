
// Rust Bitcoin Library
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Script Descriptors
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies, known
//! as "script descriptors".
//!
//! The format represents EC public keys abstractly to allow wallets to replace these with
//! BIP32 paths, pay-to-contract instructions, etc.
//!

use secp256k1;

use util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

/// Abstraction over "public key" which can be used when converting to/from a scriptpubkey
pub trait PublicKey {
    /// Convert self to public key during serialization to scriptpubkey
    fn as_pubkey(&self) -> secp256k1::PublicKey;
    /// Convert public key to self to during deserialization from scriptpubkey
    fn from_pubkey(other: secp256k1::PublicKey) -> Self;
}

impl PublicKey for secp256k1::PublicKey {
    fn as_pubkey(&self) -> secp256k1::PublicKey {
        self.clone()
    }

    fn from_pubkey(other: secp256k1::PublicKey) -> secp256k1::PublicKey {
        other
    }
}

/// Script descriptor
pub enum Descriptor<P: PublicKey> {
    /// A public key which must sign to satisfy the descriptor
    Key(P),
    /// A SHA256 whose preimage must be provided to satisfy the descriptor
    Sha256Hash(Sha256dHash),
    /// A list of descriptors, `k` of which must be satisfied
    Threshold(usize, Vec<Descriptor<P>>),
    /// A list of descriptors, all of which must be satisfied
    And(Vec<Descriptor<P>>),
    /// A pair of descriptors, one of which must be satisfied
    Or(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// Same as `Or`, but the second option is assumed to never be taken for costing purposes
    AsymmetricOr(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// A locktime restriction
    Csv(u32),
}

#[cfg(test)]
mod tests {
    use secp256k1;
    use blockdata::opcodes;
    use blockdata::script::{self, Script, ParseTree};

    use super::Descriptor;

    fn pubkeys(n: usize) -> Vec<secp256k1::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&secp, &sk[..]).expect("secret key"),
            ).expect("public key");
            ret.push(pk);
        }
        ret
    }

    #[test]
    fn compile() {
        let keys = pubkeys(10);
        let desc: Descriptor<secp256k1::PublicKey> = Descriptor::Csv(100);
        let pt = ParseTree::compile(&desc);
        assert_eq!(pt.serialize(), Script::from(vec![0x01, 0x64, 0xb2]));

        let desc = Descriptor::Key(keys[0].clone());
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
            script::Builder::new()
                .push_slice(&keys[0].serialize()[..])
                .push_opcode(opcodes::All::OP_CHECKSIG)
                .into_script()
        );

        // Liquid policy
        let desc = Descriptor::AsymmetricOr(
            Box::new(Descriptor::Threshold(3, vec![
                Descriptor::Key(keys[0].clone()),
                Descriptor::Key(keys[1].clone()),
                Descriptor::Key(keys[2].clone()),
                Descriptor::Key(keys[3].clone()),
                Descriptor::Key(keys[4].clone()),
            ])),
            Box::new(Descriptor::And(vec![
                // nb the compiler will reorder this because it can avoid the DROP if it ends with the CSV
                Descriptor::Csv(10000),
                Descriptor::Threshold(2, vec![
                    Descriptor::Key(keys[5].clone()),
                    Descriptor::Key(keys[6].clone()),
                    Descriptor::Key(keys[7].clone()),
                ]),
            ])),
        );
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
            script::Builder::new()
                .push_opcode(opcodes::All::OP_PUSHNUM_3)
                .push_slice(&keys[0].serialize()[..])
                .push_slice(&keys[1].serialize()[..])
                .push_slice(&keys[2].serialize()[..])
                .push_slice(&keys[3].serialize()[..])
                .push_slice(&keys[4].serialize()[..])
                .push_opcode(opcodes::All::OP_PUSHNUM_5)
                .push_opcode(opcodes::All::OP_CHECKMULTISIG)
                .push_opcode(opcodes::All::OP_IFDUP)
                .push_opcode(opcodes::All::OP_NOTIF)
                    .push_opcode(opcodes::All::OP_PUSHNUM_2)
                    .push_slice(&keys[5].serialize()[..])
                    .push_slice(&keys[6].serialize()[..])
                    .push_slice(&keys[7].serialize()[..])
                    .push_opcode(opcodes::All::OP_PUSHNUM_3)
                    .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
                    .push_int(10000)
                    .push_opcode(opcodes::OP_CSV)
                .push_opcode(opcodes::All::OP_ENDIF)
                .into_script()
        );
    }
}

