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

//! # Pay-to-contract-hash supporte
//! See Appendix A of the Blockstream sidechains whitepaper
//! at http://blockstream.com/sidechains.pdf for details of
//! what this does.

use secp256k1::{self, ContextFlag, Secp256k1};
use secp256k1::key::{PublicKey, SecretKey};
use blockdata::{opcodes, script};
use crypto::{hmac, sha2};
use crypto::mac::Mac;

use std::{error, fmt};

use network::constants::Network;
use util::{address, hash};

/// Encoding of "pubkey here" in script; from bitcoin core `src/script/script.h`
static PUBKEY: u8 = 0xFE;

/// A contract-hash error
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    /// Contract hashed to an out-of-range value (this is basically impossible
    /// and much more likely suggests memory corruption or hardware failure)
    BadTweak(secp256k1::Error),
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
            Error::BadTweak(ref e) |
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

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BadTweak(ref e) |
            Error::Secp(ref e) => Some(e),
            Error::Script(ref e) => Some(e),
            _ => None
        }
    }

    fn description(&self) -> &'static str {
        match *self {
            Error::BadTweak(_) => "bad public key tweak",
            Error::Secp(_) => "libsecp256k1 error",
            Error::Script(_) => "script error",
            Error::UncompressedKey => "encountered uncompressed secp public key",
            Error::ExpectedKey => "expected key when deserializing script",
            Error::ExpectedChecksig => "expected OP_*CHECKSIG* when deserializing script",
            Error::TooFewKeys(_) => "too few keys for template",
            Error::TooManyKeys(_) => "too many keys for template"
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
        let secp = Secp256k1::with_caps(ContextFlag::None);
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
                    ret.push_slice(&keys[key_index - 1].serialize_vec(&secp, true)[..])
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
                if let opcodes::Class::PushNum(n) = op.classify() {
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

/// Tweak keys using some arbitrary data
pub fn tweak_keys(secp: &Secp256k1, keys: &[PublicKey], contract: &[u8]) -> Result<Vec<PublicKey>, Error> {
    let mut ret = Vec::with_capacity(keys.len());
    for mut key in keys.iter().cloned() {
        let mut hmac_raw = [0; 32];
        let mut hmac = hmac::Hmac::new(sha2::Sha256::new(), &key.serialize_vec(secp, true));
        hmac.input(contract);
        hmac.raw_result(&mut hmac_raw);
        let hmac_sk = try!(SecretKey::from_slice(secp, &hmac_raw).map_err(Error::BadTweak));
        try!(key.add_exp_assign(secp, &hmac_sk).map_err(Error::Secp));
        ret.push(key);
    }
    Ok(ret)
}

/// Compute a tweak from some given data for the given public key
pub fn compute_tweak(secp: &Secp256k1, pk: &PublicKey, contract: &[u8]) -> Result<SecretKey, Error> {
    let mut hmac_raw = [0; 32];
    let mut hmac = hmac::Hmac::new(sha2::Sha256::new(), &pk.serialize_vec(secp, true));
    hmac.input(contract);
    hmac.raw_result(&mut hmac_raw);
    SecretKey::from_slice(secp, &hmac_raw).map_err(Error::BadTweak)
}

/// Tweak a secret key using some arbitrary data (calls `compute_tweak` internally)
pub fn tweak_secret_key(secp: &Secp256k1, key: &SecretKey, contract: &[u8]) -> Result<SecretKey, Error> {
    // Compute public key
    let pk = try!(PublicKey::from_secret_key(secp, &key).map_err(Error::Secp));
    // Compute tweak
    let hmac_sk = try!(compute_tweak(secp, &pk, contract));
    // Execute the tweak
    let mut key = *key;
    try!(key.add_assign(&secp, &hmac_sk).map_err(Error::Secp));
    // Return
    Ok(key)
}

/// Takes a contract, template and key set and runs through all the steps
pub fn create_address(secp: &Secp256k1,
                      network: Network,
                      contract: &[u8],
                      keys: &[PublicKey],
                      template: &Template)
                      -> Result<address::Address, Error> {
    let keys = try!(tweak_keys(secp, keys, contract));
    let script = try!(template.to_script(&keys));
    Ok(address::Address {
        network: network,
        ty: address::Type::ScriptHash,
        hash: hash::Hash160::from_data(&script[..])
    })
}

/// Extract the keys and template from a completed script
pub fn untemplate(script: &script::Script) -> Result<(Template, Vec<PublicKey>), Error> {
    let mut ret = script::Builder::new();
    let mut retkeys = vec![];
    let secp = Secp256k1::without_caps();

    #[derive(Copy, Clone, PartialEq, Eq)]
    enum Mode {
        SeekingKeys,
        CopyingKeys,
        SeekingCheckMulti
    }

    let mut mode = Mode::SeekingKeys;
    for instruction in script.into_iter() {
        match instruction {
            script::Instruction::PushBytes(data) => {
                let n = data.len();
                ret = match PublicKey::from_slice(&secp, data) {
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
                match op.classify() {
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
            script::Instruction::Error(e) => { return Err(Error::Script(e)); }
        }
    }
    Ok((Template::from(&ret[..]), retkeys))
}

#[cfg(test)]
mod tests {
    use secp256k1::Secp256k1;
    use secp256k1::key::PublicKey;
    use serialize::hex::FromHex;
    use rand::thread_rng;

    use blockdata::script::Script;
    use network::constants::Network;
    use util::base58::ToBase58;

    use super::*;

    macro_rules! hex (($hex:expr) => ($hex.from_hex().unwrap()));
    macro_rules! hex_key (($secp:expr, $hex:expr) => (PublicKey::from_slice($secp, &hex!($hex)).unwrap()));
    macro_rules! alpha_template(() => (Template::from(&hex!("55fefefefefefefe57AE")[..])));
    macro_rules! alpha_keys(($secp:expr) => (
        &[hex_key!($secp, "0269992fb441ae56968e5b77d46a3e53b69f136444ae65a94041fc937bdb28d933"),
          hex_key!($secp, "021df31471281d4478df85bfce08a10aab82601dca949a79950f8ddf7002bd915a"),
          hex_key!($secp, "02174c82021492c2c6dfcbfa4187d10d38bed06afb7fdcd72c880179fddd641ea1"),
          hex_key!($secp, "033f96e43d72c33327b6a4631ccaa6ea07f0b106c88b9dc71c9000bb6044d5e88a"),
          hex_key!($secp, "0313d8748790f2a86fb524579b46ce3c68fedd58d2a738716249a9f7d5458a15c2"),
          hex_key!($secp, "030b632eeb079eb83648886122a04c7bf6d98ab5dfb94cf353ee3e9382a4c2fab0"),
          hex_key!($secp, "02fb54a7fcaa73c307cfd70f3fa66a2e4247a71858ca731396343ad30c7c4009ce")]
    ));

    #[test]
    fn sanity() {
        let secp = Secp256k1::new();
        let keys = alpha_keys!(&secp);
        // This is the first withdraw ever, in alpha a94f95cc47b444c10449c0eed51d895e4970560c4a1a9d15d46124858abc3afe
        let contract = hex!("5032534894ffbf32c1f1c0d3089b27c98fd991d5d7329ebd7d711223e2cde5a9417a1fa3e852c576");

        let addr = create_address(&secp, Network::Testnet, &contract, keys, &alpha_template!()).unwrap();
        assert_eq!(addr.to_base58check(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr".to_owned());
    }

    #[test]
    fn script() {
        let secp = Secp256k1::new();
        let alpha_keys = alpha_keys!(&secp);
        let alpha_template = alpha_template!();

        let alpha_redeem = Script::from(hex!("55210269992fb441ae56968e5b77d46a3e53b69f136444ae65a94041fc937bdb28d93321021df31471281d4478df85bfce08a10aab82601dca949a79950f8ddf7002bd915a2102174c82021492c2c6dfcbfa4187d10d38bed06afb7fdcd72c880179fddd641ea121033f96e43d72c33327b6a4631ccaa6ea07f0b106c88b9dc71c9000bb6044d5e88a210313d8748790f2a86fb524579b46ce3c68fedd58d2a738716249a9f7d5458a15c221030b632eeb079eb83648886122a04c7bf6d98ab5dfb94cf353ee3e9382a4c2fab02102fb54a7fcaa73c307cfd70f3fa66a2e4247a71858ca731396343ad30c7c4009ce57ae"));
        let (template, keys) = untemplate(&alpha_redeem).unwrap();

        assert_eq!(keys, alpha_keys);
        assert_eq!(template, alpha_template);
    }

    #[test]
    fn tweak_secret() {
        let secp = Secp256k1::new();
        let (sk1, pk1) = secp.generate_keypair(&mut thread_rng()).unwrap();
        let (sk2, pk2) = secp.generate_keypair(&mut thread_rng()).unwrap();
        let (sk3, pk3) = secp.generate_keypair(&mut thread_rng()).unwrap();

        let pks = [pk1, pk2, pk3];
        let contract = b"if bottle mt dont remembr drink wont pay";

        // Directly compute tweaks on pubkeys
        let tweaked_pks = tweak_keys(&secp, &pks, &contract[..]).unwrap();
        // Compute tweaks on secret keys
        let tweaked_pk1 = PublicKey::from_secret_key(&secp, &tweak_secret_key(&secp, &sk1, &contract[..]).unwrap()).unwrap();
        let tweaked_pk2 = PublicKey::from_secret_key(&secp, &tweak_secret_key(&secp, &sk2, &contract[..]).unwrap()).unwrap();
        let tweaked_pk3 = PublicKey::from_secret_key(&secp, &tweak_secret_key(&secp, &sk3, &contract[..]).unwrap()).unwrap();
        // Check equality
        assert_eq!(tweaked_pks[0], tweaked_pk1);
        assert_eq!(tweaked_pks[1], tweaked_pk2);
        assert_eq!(tweaked_pks[2], tweaked_pk3);
    }

    #[test]
    fn bad_key_number() {
        let secp = Secp256k1::new();
        let alpha_keys = alpha_keys!(&secp);
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


