// Rust Bitcoin Library
// Written in 2015 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Pay-to-contract-hash support.
//!
//! See Appendix A of the Blockstream sidechains whitepaper at
//! <http://blockstream.com/sidechains.pdf> for details of what this does.
//!
//! This module is deprecated.

#![cfg_attr(not(test), deprecated)]

use prelude::*;

use core::fmt;
#[cfg(feature = "std")] use std::error;

use secp256k1::{self, Secp256k1};
use PrivateKey;
use PublicKey;
use hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use blockdata::{opcodes, script};

use hash_types::ScriptHash;
use network::constants::Network;
use util::address;

/// Encoding of "pubkey here" in script; from Bitcoin Core `src/script/script.h`
static PUBKEY: u8 = 0xFE;

/// A contract-hash error
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Error {
    /// Other secp256k1 related error
    Secp(secp256k1::Error),
    /// Script parsing error
    Script(script::Error),
    /// Encountered an uncompressed key in a script we were deserializing. The
    /// reserialization will compress it which might be surprising so we call
    /// this an error.
    UncompressedKey,
    /// Expected a public key when deserializing a script, but we got something else.
    ExpectedKey,
    /// Expected some sort of CHECKSIG operator when deserializing a script, but
    /// we got something else.
    ExpectedChecksig,
    /// Did not have enough keys to instantiate a script template
    TooFewKeys(usize),
    /// Had too many keys; template does not match key list
    TooManyKeys(usize)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Secp(ref e) => fmt::Display::fmt(&e, f),
            Error::Script(ref e) => fmt::Display::fmt(&e, f),
            Error::UncompressedKey => f.write_str("encountered uncompressed secp public key"),
            Error::ExpectedKey => f.write_str("expected key when deserializing script"),
            Error::ExpectedChecksig => f.write_str("expected OP_*CHECKSIG* when deserializing script"),
            Error::TooFewKeys(n) => write!(f, "got {} keys, which was not enough", n),
            Error::TooManyKeys(n) => write!(f, "got {} keys, which was too many", n)
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Secp(ref e) => Some(e),
            Error::Script(ref e) => Some(e),
            _ => None
        }
    }
}

/// An element of a script template
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum TemplateElement {
    Op(opcodes::All),
    Key
}

/// A script template
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Template(Vec<TemplateElement>);

impl Template {
    /// Instantiate a template
    pub fn to_script(&self, keys: &[PublicKey]) -> Result<script::Script, Error> {
        let mut key_index = 0;
        let mut ret = script::Builder::new();
        for elem in &self.0 {
            ret = match *elem {
                TemplateElement::Op(opcode) => ret.push_opcode(opcode),
                TemplateElement::Key => {
                    if key_index == keys.len() {
                        return Err(Error::TooFewKeys(key_index));
                    }
                    key_index += 1;
                    ret.push_key(&keys[key_index - 1])
                }
            }
        }
        if key_index == keys.len() {
            Ok(ret.into_script())
        } else {
            Err(Error::TooManyKeys(keys.len()))
        }
    }

    /// Returns the number of keys this template requires to instantiate
    pub fn required_keys(&self) -> usize {
        self.0.iter().filter(|e| **e == TemplateElement::Key).count()
    }

    /// If the first push in the template is a number, return this number. For the
    /// common case of standard multisig templates, such a number will exist and
    /// will represent the number of signatures that are required for the script
    /// to pass.
    pub fn first_push_as_number(&self) -> Option<usize> {
        if !self.0.is_empty() {
            if let TemplateElement::Op(op) = self.0[0] {
                if let opcodes::Class::PushNum(n) = op.classify(opcodes::ClassifyContext::Legacy) {
                    if n >= 0 {
                        return Some(n as usize);
                    }
                }
            }
        }
        None
    }
}

impl<'a> From<&'a [u8]> for Template {
    fn from(slice: &'a [u8]) -> Template {
        Template(slice.iter().map(|&byte| {
            if byte == PUBKEY {
                TemplateElement::Key
            } else {
                TemplateElement::Op(opcodes::All::from(byte))
            }
        }).collect())
    }
}

/// Tweak a single key using some arbitrary data
pub fn tweak_key<C: secp256k1::Verification>(secp: &Secp256k1<C>, mut key: PublicKey, contract: &[u8]) -> PublicKey {
    let hmac_result = compute_tweak(&key, contract);
    key.key.add_exp_assign(secp, &hmac_result[..]).expect("HMAC cannot produce invalid tweak");
    key
}

/// Tweak keys using some arbitrary data
pub fn tweak_keys<C: secp256k1::Verification>(secp: &Secp256k1<C>, keys: &[PublicKey], contract: &[u8]) -> Vec<PublicKey> {
    keys.iter().cloned().map(|key| tweak_key(secp, key, contract)).collect()
}

/// Compute a tweak from some given data for the given public key
pub fn compute_tweak(pk: &PublicKey, contract: &[u8]) -> Hmac<sha256::Hash> {
    let mut hmac_engine: HmacEngine<sha256::Hash> = if pk.compressed {
        HmacEngine::new(&pk.key.serialize())
    } else {
        HmacEngine::new(&pk.key.serialize_uncompressed())
    };
    hmac_engine.input(contract);
    Hmac::from_engine(hmac_engine)
}

/// Tweak a secret key using some arbitrary data (calls `compute_tweak` internally)
pub fn tweak_secret_key<C: secp256k1::Signing>(secp: &Secp256k1<C>, key: &PrivateKey, contract: &[u8]) -> Result<PrivateKey, Error> {
    // Compute public key
    let pk = PublicKey::from_private_key(secp, key);
    // Compute tweak
    let hmac_sk = compute_tweak(&pk, contract);
    // Execute the tweak
    let mut key = *key;
    key.key.add_assign(&hmac_sk[..]).map_err(Error::Secp)?;
    // Return
    Ok(key)
}

/// Takes a contract, template and key set and runs through all the steps
pub fn create_address<C: secp256k1::Verification>(secp: &Secp256k1<C>,
                      network: Network,
                      contract: &[u8],
                      keys: &[PublicKey],
                      template: &Template)
                      -> Result<address::Address, Error> {
    let keys = tweak_keys(secp, keys, contract);
    let script = template.to_script(&keys)?;
    Ok(address::Address {
        network,
        payload: address::Payload::ScriptHash(
            ScriptHash::hash(&script[..])
        )
    })
}

/// Extract the keys and template from a completed script
pub fn untemplate(script: &script::Script) -> Result<(Template, Vec<PublicKey>), Error> {
    let mut ret = script::Builder::new();
    let mut retkeys = vec![];

    #[derive(Copy, Clone, PartialEq, Eq)]
    enum Mode {
        SeekingKeys,
        CopyingKeys,
        SeekingCheckMulti
    }

    let mut mode = Mode::SeekingKeys;
    for instruction in script.instructions() {
        if let Err(e) = instruction {
            return Err(Error::Script(e));
        }
        match instruction.unwrap() {
            script::Instruction::PushBytes(data) => {
                let n = data.len();
                ret = match PublicKey::from_slice(data) {
                    Ok(key) => {
                        if n == 65 { return Err(Error::UncompressedKey); }
                        if mode == Mode::SeekingCheckMulti { return Err(Error::ExpectedChecksig); }
                        retkeys.push(key);
                        mode = Mode::CopyingKeys;
                        ret.push_opcode(opcodes::All::from(PUBKEY))
                    }
                    Err(_) => {
                        // Arbitrary pushes are only allowed before we've found any keys.
                        // Otherwise we have to wait for a N CHECKSIG pair.
                        match mode {
                            Mode::SeekingKeys => { ret.push_slice(data) }
                            Mode::CopyingKeys => { return Err(Error::ExpectedKey); },
                            Mode::SeekingCheckMulti => { return Err(Error::ExpectedChecksig); }
                        }
                    }
                }
            }
            script::Instruction::Op(op) => {
                match op.classify(opcodes::ClassifyContext::Legacy) {
                    // CHECKSIG should only come after a list of keys
                    opcodes::Class::Ordinary(opcodes::Ordinary::OP_CHECKSIG) |
                    opcodes::Class::Ordinary(opcodes::Ordinary::OP_CHECKSIGVERIFY) => {
                        if mode == Mode::SeekingKeys { return Err(Error::ExpectedKey); }
                        mode = Mode::SeekingKeys;
                    }
                    // CHECKMULTISIG should only come after a number
                    opcodes::Class::Ordinary(opcodes::Ordinary::OP_CHECKMULTISIG) |
                    opcodes::Class::Ordinary(opcodes::Ordinary::OP_CHECKMULTISIGVERIFY) => {
                        if mode == Mode::SeekingKeys { return Err(Error::ExpectedKey); }
                        if mode == Mode::CopyingKeys { return Err(Error::ExpectedKey); }
                        mode = Mode::SeekingKeys;
                    }
                    // Numbers after keys mean we expect a CHECKMULTISIG.
                    opcodes::Class::PushNum(_) => {
                        if mode == Mode::SeekingCheckMulti { return Err(Error::ExpectedChecksig); }
                        if mode == Mode::CopyingKeys { mode = Mode::SeekingCheckMulti; }
                    }
                    // All other opcodes do nothing
                    _ => {}
                }
                ret = ret.push_opcode(op);
            }
        }
    }
    Ok((Template::from(&ret[..]), retkeys))
}

#[cfg(test)]
mod tests {
    use secp256k1::Secp256k1;
    use hashes::hex::FromHex;
    use secp256k1::rand::thread_rng;
    use core::str::FromStr;

    use blockdata::script::Script;
    use network::constants::Network;

    use super::*;
    use PublicKey;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_key (($hex:expr) => (PublicKey::from_slice(&hex!($hex)).unwrap()));
    macro_rules! alpha_template(() => (Template::from(&hex!("55fefefefefefefe57AE")[..])));
    macro_rules! alpha_keys(() => (
        &[hex_key!("0269992fb441ae56968e5b77d46a3e53b69f136444ae65a94041fc937bdb28d933"),
          hex_key!("021df31471281d4478df85bfce08a10aab82601dca949a79950f8ddf7002bd915a"),
          hex_key!("02174c82021492c2c6dfcbfa4187d10d38bed06afb7fdcd72c880179fddd641ea1"),
          hex_key!("033f96e43d72c33327b6a4631ccaa6ea07f0b106c88b9dc71c9000bb6044d5e88a"),
          hex_key!("0313d8748790f2a86fb524579b46ce3c68fedd58d2a738716249a9f7d5458a15c2"),
          hex_key!("030b632eeb079eb83648886122a04c7bf6d98ab5dfb94cf353ee3e9382a4c2fab0"),
          hex_key!("02fb54a7fcaa73c307cfd70f3fa66a2e4247a71858ca731396343ad30c7c4009ce")]
    ));

    #[test]
    fn sanity() {
        let secp = Secp256k1::new();
        let keys = alpha_keys!();
        // This is the first withdraw ever, in alpha a94f95cc47b444c10449c0eed51d895e4970560c4a1a9d15d46124858abc3afe
        let contract = hex!("5032534894ffbf32c1f1c0d3089b27c98fd991d5d7329ebd7d711223e2cde5a9417a1fa3e852c576");

        let addr = create_address(&secp, Network::Testnet, &contract, keys, &alpha_template!()).unwrap();
        assert_eq!(addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr".to_owned());
    }

    #[test]
    fn script() {
        let alpha_keys = alpha_keys!();
        let alpha_template = alpha_template!();

        let alpha_redeem = Script::from(hex!("55210269992fb441ae56968e5b77d46a3e53b69f136444ae65a94041fc937bdb28d93321021df31471281d4478df85bfce08a10aab82601dca949a79950f8ddf7002bd915a2102174c82021492c2c6dfcbfa4187d10d38bed06afb7fdcd72c880179fddd641ea121033f96e43d72c33327b6a4631ccaa6ea07f0b106c88b9dc71c9000bb6044d5e88a210313d8748790f2a86fb524579b46ce3c68fedd58d2a738716249a9f7d5458a15c221030b632eeb079eb83648886122a04c7bf6d98ab5dfb94cf353ee3e9382a4c2fab02102fb54a7fcaa73c307cfd70f3fa66a2e4247a71858ca731396343ad30c7c4009ce57ae"));
        let (template, keys) = untemplate(&alpha_redeem).unwrap();

        assert_eq!(keys, alpha_keys);
        assert_eq!(template, alpha_template);
    }

    #[test]
    fn tweak_secret() {
        let secp = Secp256k1::new();
        let (sk1, pk1) = secp.generate_keypair(&mut thread_rng());
        let (sk2, pk2) = secp.generate_keypair(&mut thread_rng());
        let (sk3, pk3) = secp.generate_keypair(&mut thread_rng());

        let sk1 = PrivateKey::new(sk1, Network::Bitcoin);
        let sk2 = PrivateKey::new_uncompressed(sk2, Network::Bitcoin);
        let sk3 = PrivateKey::new(sk3, Network::Bitcoin);
        let pks = [
            PublicKey::new(pk1),
            PublicKey::new_uncompressed(pk2),
            PublicKey::new(pk3),
        ];
        let contract = b"if bottle mt dont remembr drink wont pay";

        // Directly compute tweaks on pubkeys
        let tweaked_pks = tweak_keys(&secp, &pks, &contract[..]);
        // Compute tweaks on secret keys
        let tweaked_pk1 = PublicKey::from_private_key(&secp, &tweak_secret_key(&secp, &sk1, &contract[..]).unwrap());
        let tweaked_pk2 = PublicKey::from_private_key(&secp, &tweak_secret_key(&secp, &sk2, &contract[..]).unwrap());
        let tweaked_pk3 = PublicKey::from_private_key(&secp, &tweak_secret_key(&secp, &sk3, &contract[..]).unwrap());
        // Check equality
        assert_eq!(tweaked_pks[0], tweaked_pk1);
        assert_eq!(tweaked_pks[1], tweaked_pk2);
        assert_eq!(tweaked_pks[2], tweaked_pk3);
    }

    #[test]
    fn tweak_fixed_vector() {
        let secp = Secp256k1::new();

        let pks = [
            PublicKey::from_str("02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c").unwrap(),
            PublicKey::from_str("0365c0755ea55ce85d8a1900c68a524dbfd1c0db45ac3b3840dbb10071fe55e7a8").unwrap(),
            PublicKey::from_str("0202313ca315889b2e69c94cf86901119321c7288139ba53ac022b7af3dc250054").unwrap(),
        ];
        let tweaked_pks = [
            PublicKey::from_str("03b3597221b5982a3f1a77aed50f0015d1b6edfc69023ef7f25cfac0e8af1b2041").unwrap(),
            PublicKey::from_str("0296ece1fd954f7ae94f8d6bad19fd6d583f5b36335cf13135a3053a22f3c1fb05").unwrap(),
            PublicKey::from_str("0230bb1ca5dbc7fcf49294c2c3e582e5582eabf7c87e885735dc774da45d610e51").unwrap(),
        ];
        let contract = b"if bottle mt dont remembr drink wont pay";

        // Directly compute tweaks on pubkeys
        assert_eq!(
            tweak_keys(&secp, &pks, &contract[..]),
            tweaked_pks
        );
    }

    #[test]
    fn bad_key_number() {
        let alpha_keys = alpha_keys!();
        let template_short = Template::from(&hex!("55fefefefefefe57AE")[..]);
        let template_long = Template::from(&hex!("55fefefefefefefefe57AE")[..]);
        let template = Template::from(&hex!("55fefefefefefefe57AE")[..]);

        assert_eq!(template_short.required_keys(), 6);
        assert_eq!(template_long.required_keys(), 8);
        assert_eq!(template.required_keys(), 7);
        assert_eq!(template_short.to_script(alpha_keys), Err(Error::TooManyKeys(7)));
        assert_eq!(template_long.to_script(alpha_keys), Err(Error::TooFewKeys(7)));
        assert!(template.to_script(alpha_keys).is_ok());
    }
}


