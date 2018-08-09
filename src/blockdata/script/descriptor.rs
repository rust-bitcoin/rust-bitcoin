
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

use std::collections::HashMap;
use std::hash::Hash;

use secp256k1;

use util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

/// Descriptor error
pub enum Error {
    /// During instantiation, was missing data needed to instantiate a key
    MissingKeyAux,
}

/// Abstraction over "public key" which can be used when converting to/from a scriptpubkey
pub trait PublicKey: Hash + Eq {
    /// Auxiallary data needed to convert this public key into a secp public key
    type Aux;

    /// Convert self to public key during serialization to scriptpubkey
    fn instantiate(&self, aux: Option<&Self::Aux>) -> Result<secp256k1::PublicKey, Error>;
}

impl PublicKey for secp256k1::PublicKey {
    type Aux = ();

    fn instantiate(&self, _: Option<&()>) -> Result<secp256k1::PublicKey, Error> {
        Ok(self.clone())
    }
}

/// Script descriptor
pub enum Descriptor<P: PublicKey> {
    /// A public key which must sign to satisfy the descriptor
    Key(P),
    /// A public key which must sign to satisfy the descriptor (pay-to-pubkey-hash form)
    KeyHash(P),
    /// A set of keys, signatures must be provided for `k` of them
    Multi(usize, Vec<P>),
    /// A SHA256 whose preimage must be provided to satisfy the descriptor
    Hash(Sha256dHash),
    /// A list of descriptors, all of which must be satisfied
    And(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// A pair of descriptors, one of which must be satisfied
    Or(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// Same as `Or`, but the second option is assumed to never be taken for costing purposes
    AsymmetricOr(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// A locktime restriction
    Time(u32),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(P),
    /// Pay-to-ScriptHash
    Sh(Box<Descriptor<P>>),
    /// Pay-to-Witness-ScriptHash
    Wsh(Box<Descriptor<P>>),
}

impl<P: PublicKey> Descriptor<P> {
    /// Convert a descriptor using abstract keys to one using specific keys
    pub fn instantiate(&self, keymap: &HashMap<P, P::Aux>) -> Result<Descriptor<secp256k1::PublicKey>, Error> {
        match *self {
            Descriptor::Key(ref pk) => {
                let secp_pk = pk.instantiate(keymap.get(pk))?;
                Ok(Descriptor::Key(secp_pk))
            }
            Descriptor::KeyHash(ref pk) => {
                let secp_pk = pk.instantiate(keymap.get(pk))?;
                Ok(Descriptor::KeyHash(secp_pk))
            }
            Descriptor::Multi(k, ref keys) => {
                let mut new_keys = Vec::with_capacity(keys.len());
                for key in keys {
                    let secp_pk = key.instantiate(keymap.get(key))?;
                    new_keys.push(secp_pk);
                }
                Ok(Descriptor::Multi(k, new_keys))
            }
            Descriptor::Hash(hash) => Ok(Descriptor::Hash(hash)),
            Descriptor::And(ref left, ref right) => {
                Ok(Descriptor::And(
                    Box::new(left.instantiate(keymap)?),
                    Box::new(right.instantiate(keymap)?)
                ))
            }
            Descriptor::Or(ref left, ref right) => {
                Ok(Descriptor::Or(
                    Box::new(left.instantiate(keymap)?),
                    Box::new(right.instantiate(keymap)?)
                ))
            }
            Descriptor::AsymmetricOr(ref left, ref right) => {
                Ok(Descriptor::AsymmetricOr(
                    Box::new(left.instantiate(keymap)?),
                    Box::new(right.instantiate(keymap)?)
                ))
            }
            Descriptor::Time(n) => Ok(Descriptor::Time(n)),
            Descriptor::Wpkh(ref pk) => {
                let secp_pk = pk.instantiate(keymap.get(pk))?;
                Ok(Descriptor::Wpkh(secp_pk))
            }
            Descriptor::Sh(ref desc) => {
                Ok(Descriptor::Sh(Box::new(desc.instantiate(keymap)?)))
            }
            Descriptor::Wsh(ref desc) => {
                Ok(Descriptor::Wsh(Box::new(desc.instantiate(keymap)?)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1;

    use blockdata::opcodes;
    use blockdata::script::{self, Descriptor, ParseTree, Script};

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
        let desc: Descriptor<secp256k1::PublicKey> = Descriptor::Time(100);
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

        // CSV reordering trick
        let desc = Descriptor::And(
            // nb the compiler will reorder this because it can avoid the DROP if it ends with the CSV
            Box::new(Descriptor::Time(10000)),
            Box::new(Descriptor::Multi(2, keys[5..8].to_owned())),
        );
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
            script::Builder::new()
                .push_opcode(opcodes::All::OP_PUSHNUM_2)
                .push_slice(&keys[5].serialize()[..])
                .push_slice(&keys[6].serialize()[..])
                .push_slice(&keys[7].serialize()[..])
                .push_opcode(opcodes::All::OP_PUSHNUM_3)
                .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
                .push_int(10000)
                .push_opcode(opcodes::OP_CSV)
                .into_script()
        );

        // Liquid policy
        let desc = Descriptor::AsymmetricOr(
            Box::new(Descriptor::Multi(3, keys[0..5].to_owned())),
            Box::new(Descriptor::And(
                Box::new(Descriptor::Time(10000)),
                Box::new(Descriptor::Multi(2, keys[5..8].to_owned())),
            )),
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

