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
    /// Did not have enough keys to instantiate a script template
    TooFewKeys(usize)
}

/// An element of a script template
enum TemplateElement {
    Op(opcodes::All),
    Key
}

/// A script template
pub struct Template(Vec<TemplateElement>);

impl Template {
    /// Instantiate a template
    pub fn to_script(&self, keys: &[PublicKey]) -> Result<script::Script, Error> {
        let secp = Secp256k1::with_caps(ContextFlag::None);
        let mut key_index = 0;
        let mut ret = script::Builder::new();
        for elem in &self.0 {
            match *elem {
                TemplateElement::Op(opcode) => ret.push_opcode(opcode),
                TemplateElement::Key => {
                    if key_index == keys.len() {
                        return Err(Error::TooFewKeys(key_index));
                    }
                    ret.push_slice(&keys[key_index].serialize_vec(&secp, true)[..]);
                    key_index += 1;
                }
            }
        }
        Ok(ret.into_script())
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
        let mut hmac = hmac::Hmac::new(sha2::Sha256::new(), &key.serialize_vec(&secp, true));
        hmac.input(contract);
        hmac.raw_result(&mut hmac_raw);
        let hmac_sk = try!(SecretKey::from_slice(&secp, &hmac_raw).map_err(Error::BadTweak));
        try!(key.add_exp_assign(&secp, &hmac_sk).map_err(Error::Secp));
        ret.push(key);
    }
    Ok(ret)
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

#[cfg(test)]
mod tests {
    use secp256k1::Secp256k1;
    use secp256k1::key::PublicKey;
    use serialize::hex::FromHex;

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
}


