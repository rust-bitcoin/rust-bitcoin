// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # BIP32 Implementation
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use std::default::Default;
use std::io::extensions::{u64_to_be_bytes, u64_from_be_bytes};
use serialize::{Decoder, Decodable, Encoder, Encodable};

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::ripemd160::Ripemd160;
use crypto::sha2::Sha256;
use crypto::sha2::Sha512;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1;

use network::constants::{Network, Bitcoin, BitcoinTestnet};
use util::base58::{Base58Error,
                   InvalidLength, InvalidVersion, OtherBase58Error,
                   FromBase58, ToBase58};

/// A chain code
pub struct ChainCode([u8, ..32]);
impl_array_newtype!(ChainCode, u8, 32)
impl_array_newtype_show!(ChainCode)
impl_array_newtype_encodable!(ChainCode, u8, 32)

/// A fingerprint
pub struct Fingerprint([u8, ..4]);
impl_array_newtype!(Fingerprint, u8, 4)
impl_array_newtype_show!(Fingerprint)
impl_array_newtype_encodable!(Fingerprint, u8, 4)

impl Default for Fingerprint {
  fn default() -> Fingerprint { Fingerprint([0, 0, 0, 0]) }
}

/// Extended private key
#[deriving(Clone, PartialEq, Eq, Encodable, Decodable, Show)]
pub struct ExtendedPrivKey {
  /// The network this key is to be used on
  pub network: Network,
  /// How many derivations this key is from the master (which is 0)
  pub depth: uint,
  /// Fingerprint of the parent key (0 for master)
  pub parent_fingerprint: Fingerprint,
  /// Child number of the key used to derive from parent (0 for master)
  pub child_number: ChildNumber,
  /// Secret key
  pub secret_key: SecretKey,
  /// Chain code
  pub chain_code: ChainCode
}

/// Extended public key
#[deriving(Clone, PartialEq, Eq, Encodable, Decodable, Show)]
pub struct ExtendedPubKey {
  /// The network this key is to be used on
  pub network: Network,
  /// How many derivations this key is from the master (which is 0)
  pub depth: uint,
  /// Fingerprint of the parent key
  pub parent_fingerprint: Fingerprint,
  /// Child number of the key used to derive from parent (0 for master)
  pub child_number: ChildNumber,
  /// Public key
  pub public_key: PublicKey,
  /// Chain code
  pub chain_code: ChainCode
}

/// A child number for a derived key
#[deriving(Clone, PartialEq, Eq, Show)]
pub enum ChildNumber {
  /// Hardened key index, within [0, 2^31 - 1]
  Hardened(u32),
  /// Non-hardened key, within [0, 2^31 - 1]
  Normal(u32),
}

impl<S: Encoder<E>, E> Encodable<S, E> for ChildNumber {
  fn encode(&self, s: &mut S) -> Result<(), E> {
    match *self {
      Hardened(n) => (n + (1 << 31)).encode(s),
      Normal(n)   => n.encode(s)
    }
  }
}

impl<D: Decoder<E>, E> Decodable<D, E> for ChildNumber {
  fn decode(d: &mut D) -> Result<ChildNumber, E> { 
    let n: u32 = try!(Decodable::decode(d));
    if n < (1 << 31) {
      Ok(Normal(n))
    } else {
      Ok(Hardened(n - (1 << 31)))
    }
  }
}

/// A BIP32 error
#[deriving(Clone, PartialEq, Eq, Show)]
pub enum Error {
  /// A pk->pk derivation was attempted on a hardened key
  CannotDeriveFromHardenedKey,
  /// A secp256k1 error occured
  EcdsaError(secp256k1::Error),
  /// A child number was provided that was out of range
  InvalidChildNumber(ChildNumber),
  /// Error creating a master seed --- for application use
  RngError(String)
}

impl ExtendedPrivKey {
  /// Construct a new master key from a seed value
  pub fn new_master(network: Network, seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
    let mut result = [0, ..64];
    let mut hmac = Hmac::new(Sha512::new(), b"Bitcoin seed".as_slice());
    hmac.input(seed);
    hmac.raw_result(result.as_mut_slice());

    Ok(ExtendedPrivKey {
      network: network,
      depth: 0,
      parent_fingerprint: Default::default(),
      child_number: Normal(0),
      secret_key: try!(SecretKey::from_slice(result.slice_to(32)).map_err(EcdsaError)),
      chain_code: ChainCode::from_slice(result.slice_from(32))
    })
  }

  /// Creates a privkey from a path
  pub fn from_path(master: &ExtendedPrivKey, path: &[ChildNumber])
                   -> Result<ExtendedPrivKey, Error> {
    let mut sk = *master;
    for &num in path.iter() {
      sk = try!(sk.ckd_priv(num));
    }
    Ok(sk)
  }

  /// Private->Private child key derivation
  pub fn ckd_priv(&self, i: ChildNumber) -> Result<ExtendedPrivKey, Error> {
    let mut result = [0, ..64];
    let mut hmac = Hmac::new(Sha512::new(), self.chain_code.as_slice());
    match i {
      Normal(n) => {
        if n >= (1 << 31) { return Err(InvalidChildNumber(i)) }
        // Non-hardened key: compute public data and use that
        secp256k1::init();
        // Note the unwrap: this is fine, we checked the SK when we created it
        hmac.input(PublicKey::from_secret_key(&self.secret_key, true).as_slice());
        u64_to_be_bytes(n as u64, 4, |raw| hmac.input(raw));
      }
      Hardened(n) => {
        if n >= (1 << 31) { return Err(InvalidChildNumber(i)) }
        // Hardened key: use only secret data to prevent public derivation
        hmac.input([0]);
        hmac.input(self.secret_key.as_slice());
        u64_to_be_bytes(n as u64 + (1 << 31), 4, |raw| hmac.input(raw));
      }
    }
    hmac.raw_result(result.as_mut_slice());
    let mut sk = try!(SecretKey::from_slice(result.slice_to(32)).map_err(EcdsaError));
    try!(sk.add_assign(&self.secret_key).map_err(EcdsaError));

    Ok(ExtendedPrivKey {
      network: self.network,
      depth: self.depth + 1,
      parent_fingerprint: self.fingerprint(),
      child_number: i,
      secret_key: sk,
      chain_code: ChainCode::from_slice(result.slice_from(32))
    })
  }

  /// Returns the HASH160 of the chaincode
  pub fn identifier(&self) -> [u8, ..20] {
    let mut sha2_res = [0, ..32];
    let mut ripemd_res = [0, ..20];
    // Compute extended public key
    let pk = ExtendedPubKey::from_private(self);
    // Do SHA256 of just the ECDSA pubkey
    let mut sha2 = Sha256::new();
    sha2.input(pk.public_key.as_slice());
    sha2.result(sha2_res.as_mut_slice());
    // do RIPEMD160
    let mut ripemd = Ripemd160::new();
    ripemd.input(sha2_res.as_slice());
    ripemd.result(ripemd_res.as_mut_slice());
    // Return
    ripemd_res
  }

  /// Returns the first four bytes of the identifier
  pub fn fingerprint(&self) -> Fingerprint {
    Fingerprint::from_slice(self.identifier().slice_to(4))
  }
}

impl ExtendedPubKey {
  /// Derives a public key from a private key
  pub fn from_private(sk: &ExtendedPrivKey) -> ExtendedPubKey {
    secp256k1::init();
    ExtendedPubKey {
      network: sk.network,
      depth: sk.depth,
      parent_fingerprint: sk.parent_fingerprint,
      child_number: sk.child_number,
      public_key: PublicKey::from_secret_key(&sk.secret_key, true),
      chain_code: sk.chain_code
    }
  }

  /// Public->Public child key derivation
  pub fn ckd_pub(&self, i: ChildNumber) -> Result<ExtendedPubKey, Error> {
    match i {
      Hardened(n) => {
        if n >= (1 << 31) {
          Err(InvalidChildNumber(i))
        } else {
          Err(CannotDeriveFromHardenedKey)
        }
      }
      Normal(n) => {
        let mut hmac = Hmac::new(Sha512::new(), self.chain_code.as_slice());
        hmac.input(self.public_key.as_slice());
        u64_to_be_bytes(n as u64, 4, |raw| hmac.input(raw));

        let mut result = [0, ..64];
        hmac.raw_result(result.as_mut_slice());

        let sk = try!(SecretKey::from_slice(result.slice_to(32)).map_err(EcdsaError));
        let mut pk = self.public_key.clone();
        try!(pk.add_exp_assign(&sk).map_err(EcdsaError));

        Ok(ExtendedPubKey {
          network: self.network,
          depth: self.depth + 1,
          parent_fingerprint: self.fingerprint(),
          child_number: i,
          public_key: pk,
          chain_code: ChainCode::from_slice(result.slice_from(32))
        })
      }
    }
  }

  /// Returns the HASH160 of the chaincode
  pub fn identifier(&self) -> [u8, ..20] {
    let mut sha2_res = [0, ..32];
    let mut ripemd_res = [0, ..20];
    // Do SHA256 of just the ECDSA pubkey
    let mut sha2 = Sha256::new();
    sha2.input(self.public_key.as_slice());
    sha2.result(sha2_res.as_mut_slice());
    // do RIPEMD160
    let mut ripemd = Ripemd160::new();
    ripemd.input(sha2_res.as_slice());
    ripemd.result(ripemd_res.as_mut_slice());
    // Return
    ripemd_res
  }

  /// Returns the first four bytes of the identifier
  pub fn fingerprint(&self) -> Fingerprint {
    Fingerprint::from_slice(self.identifier().slice_to(4))
  }
}

impl ToBase58 for ExtendedPrivKey {
  fn base58_layout(&self) -> Vec<u8> { 
    let mut ret = Vec::with_capacity(78);
    ret.push_all(match self.network {
      Bitcoin => [0x04, 0x88, 0xAD, 0xE4],
      BitcoinTestnet => [0x04, 0x35, 0x83, 0x94]
    });
    ret.push(self.depth as u8);
    ret.push_all(self.parent_fingerprint.as_slice());
    match self.child_number {
      Hardened(n) => {
        u64_to_be_bytes(n as u64 + (1 << 31), 4, |raw| ret.push_all(raw));
      }
      Normal(n) => {
        u64_to_be_bytes(n as u64, 4, |raw| ret.push_all(raw));
      }
    }
    ret.push_all(self.chain_code.as_slice());
    ret.push(0);
    ret.push_all(self.secret_key.as_slice());
    ret
  }
}

impl FromBase58 for ExtendedPrivKey {
  fn from_base58_layout(data: Vec<u8>) -> Result<ExtendedPrivKey, Base58Error> {
    if data.len() != 78 {
      return Err(InvalidLength(data.len()));
    }

    let cn_int = u64_from_be_bytes(data.as_slice(), 9, 4) as u32;
    let child_number = if cn_int < (1 << 31) { Normal(cn_int) }
                       else { Hardened(cn_int - (1 << 31)) };

    Ok(ExtendedPrivKey {
      network: match data.slice_to(4) {
        [0x04, 0x88, 0xAD, 0xE4] => Bitcoin,
        [0x04, 0x35, 0x83, 0x94] => BitcoinTestnet,
        _ => { return Err(InvalidVersion(data.slice_to(4).to_vec())); }
      },
      depth: data[4] as uint,
      parent_fingerprint: Fingerprint::from_slice(data.slice(5, 9)),
      child_number: child_number,
      chain_code: ChainCode::from_slice(data.slice(13, 45)),
      secret_key: try!(SecretKey::from_slice(
                         data.slice(46, 78)).map_err(|e|
                           OtherBase58Error(e.to_string())))
    })
  }
}

impl ToBase58 for ExtendedPubKey {
  fn base58_layout(&self) -> Vec<u8> {
    assert!(self.public_key.is_compressed());
    let mut ret = Vec::with_capacity(78);
    ret.push_all(match self.network {
      Bitcoin => [0x04, 0x88, 0xB2, 0x1E],
      BitcoinTestnet => [0x04, 0x35, 0x87, 0xCF]
    });
    ret.push(self.depth as u8);
    ret.push_all(self.parent_fingerprint.as_slice());
    match self.child_number {
      Hardened(n) => {
        u64_to_be_bytes(n as u64 + (1 << 31), 4, |raw| ret.push_all(raw));
      }
      Normal(n) => {
        u64_to_be_bytes(n as u64, 4, |raw| ret.push_all(raw));
      }
    }
    ret.push_all(self.chain_code.as_slice());
    ret.push_all(self.public_key.as_slice());
    ret
  }
}

impl FromBase58 for ExtendedPubKey {
  fn from_base58_layout(data: Vec<u8>) -> Result<ExtendedPubKey, Base58Error> {
    if data.len() != 78 {
      return Err(InvalidLength(data.len()));
    }

    let cn_int = u64_from_be_bytes(data.as_slice(), 9, 4) as u32;
    let child_number = if cn_int < (1 << 31) { Normal(cn_int) }
                       else { Hardened(cn_int - (1 << 31)) };

    Ok(ExtendedPubKey {
      network: match data.slice_to(4) {
        [0x04, 0x88, 0xB2, 0x1E] => Bitcoin,
        [0x04, 0x35, 0x87, 0xCF] => BitcoinTestnet,
        _ => { return Err(InvalidVersion(data.slice_to(4).to_vec())); }
      },
      depth: data[4] as uint,
      parent_fingerprint: Fingerprint::from_slice(data.slice(5, 9)),
      child_number: child_number,
      chain_code: ChainCode::from_slice(data.slice(13, 45)),
      public_key: try!(PublicKey::from_slice(
                         data.slice(45, 78)).map_err(|e|
                           OtherBase58Error(e.to_string())))
    })
  }
}

#[cfg(test)]
mod tests {
  use serialize::hex::FromHex;
  use test::{Bencher, black_box};

  use network::constants::{Network, Bitcoin};
  use util::base58::{FromBase58, ToBase58};

  use super::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, Hardened, Normal};

  fn test_path(network: Network,
               seed: &[u8],
               path: &[ChildNumber],
               expected_sk: &str,
               expected_pk: &str) {

    let mut sk = ExtendedPrivKey::new_master(network, seed).unwrap();
    let mut pk = ExtendedPubKey::from_private(&sk);
    // Derive keys, checking hardened and non-hardened derivation
    for &num in path.iter() {
      sk = sk.ckd_priv(num).unwrap();
      match num {
        Normal(_) => {
          let pk2 = pk.ckd_pub(num).unwrap();
          pk = ExtendedPubKey::from_private(&sk);
          assert_eq!(pk, pk2);
        }
        Hardened(_) => {
          pk = ExtendedPubKey::from_private(&sk);
        }
      }
    }

    // Check result against expected base58
    assert_eq!(sk.to_base58check().as_slice(), expected_sk);
    assert_eq!(pk.to_base58check().as_slice(), expected_pk);
    // Check decoded base58 against result
    let decoded_sk = FromBase58::from_base58check(expected_sk);
    let decoded_pk = FromBase58::from_base58check(expected_pk);
    assert_eq!(Ok(sk), decoded_sk);
    assert_eq!(Ok(pk), decoded_pk);
  }

  #[test]
  fn test_vector_1() {
    let seed = "000102030405060708090a0b0c0d0e0f".from_hex().unwrap();
    // m
    test_path(Bitcoin, seed.as_slice(), [],
              "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
               "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
              
    // m/0h
    test_path(Bitcoin, seed.as_slice(), [Hardened(0)],
              "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
              "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");

    // m/0h/1
    test_path(Bitcoin, seed.as_slice(), [Hardened(0), Normal(1)],
               "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
               "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");

    // m/0h/1/2h
    test_path(Bitcoin, seed.as_slice(), [Hardened(0), Normal(1), Hardened(2)],
              "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
              "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");

    // m/0h/1/2h/2
    test_path(Bitcoin, seed.as_slice(), [Hardened(0), Normal(1), Hardened(2), Normal(2)],
              "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
              "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");

    // m/0h/1/2h/2/1000000000
    test_path(Bitcoin, seed.as_slice(), [Hardened(0), Normal(1), Hardened(2), Normal(2), Normal(1000000000)],
              "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
              "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
  }

  #[test]
  fn test_vector_2() {
    let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".from_hex().unwrap();

    // m
    test_path(Bitcoin, seed.as_slice(), [],
              "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
              "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");

    // m/0
    test_path(Bitcoin, seed.as_slice(), [Normal(0)],
              "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
              "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");

    // m/0/2147483647h
    test_path(Bitcoin, seed.as_slice(), [Normal(0), Hardened(2147483647)],
              "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
              "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");

    // m/0/2147483647h/1
    test_path(Bitcoin, seed.as_slice(), [Normal(0), Hardened(2147483647), Normal(1)],
              "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
              "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");

    // m/0/2147483647h/1/2147483646h
    test_path(Bitcoin, seed.as_slice(), [Normal(0), Hardened(2147483647), Normal(1), Hardened(2147483646)],
              "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
              "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");

    // m/0/2147483647h/1/2147483646h/2
    test_path(Bitcoin, seed.as_slice(), [Normal(0), Hardened(2147483647), Normal(1), Hardened(2147483646), Normal(2)],
              "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
              "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
  }

  #[test]
  pub fn encode_decode_childnumber() {
    use serialize::json;

    let h1 = Hardened(1);
    let n1 = Normal(1);

    let h1_str = json::encode(&h1);
    let n1_str = json::encode(&n1);

    assert!(h1 != n1);
    assert!(h1_str != n1_str);

    let h1_dec = json::decode(h1_str.as_slice()).unwrap();
    let n1_dec = json::decode(n1_str.as_slice()).unwrap();
    assert_eq!(h1, h1_dec);
    assert_eq!(n1, n1_dec);
  }

  #[bench]
  pub fn generate_sequential_normal_children(bh: &mut Bencher) {
    let seed = "000102030405060708090a0b0c0d0e0f".from_hex().unwrap();
    let msk = ExtendedPrivKey::new_master(Bitcoin, seed.as_slice()).unwrap();
    let mut i = 0;
    bh.iter( || {
      black_box(msk.ckd_priv(Normal(i)));
      i += 1;
    })
  }

  #[bench]
  pub fn generate_sequential_hardened_children(bh: &mut Bencher) {
    let seed = "000102030405060708090a0b0c0d0e0f".from_hex().unwrap();
    let msk = ExtendedPrivKey::new_master(Bitcoin, seed.as_slice()).unwrap();
    let mut i = 0;
    bh.iter( || {
      black_box(msk.ckd_priv(Hardened(i)));
      i += 1;
    })
  }

  #[bench]
  pub fn generate_sequential_public_children(bh: &mut Bencher) {
    let seed = "000102030405060708090a0b0c0d0e0f".from_hex().unwrap();
    let msk = ExtendedPrivKey::new_master(Bitcoin, seed.as_slice()).unwrap();
    let mpk = ExtendedPubKey::from_private(&msk);

    let mut i = 0;
    bh.iter( || {
      black_box(mpk.ckd_pub(Normal(i)));
      i += 1;
    })
  }

  #[bench]
  pub fn generate_sequential_public_child_addresses(bh: &mut Bencher) {
    use wallet::address::Address;

    let seed = "000102030405060708090a0b0c0d0e0f".from_hex().unwrap();
    let msk = ExtendedPrivKey::new_master(Bitcoin, seed.as_slice()).unwrap();
    let mpk = ExtendedPubKey::from_private(&msk);

    let mut i = 0;
    bh.iter( || {
      let epk = mpk.ckd_pub(Normal(i)).unwrap();
      black_box(Address::from_key(Bitcoin, &epk.public_key));
      i += 1;
    })
  }
}

