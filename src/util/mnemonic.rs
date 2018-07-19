// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
//! # BIP39 Implementation
//!
//! Implementation of BIP39 Mnemonic code for generating deterministic keys, as defined
//! at https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

use crypto::pbkdf2::pbkdf2;
use crypto::sha2::{Sha256, Sha512};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use std::fmt;


lazy_static! {
	/// List of bip39 words
	pub static ref WORDS: Vec<String> = { include_str!("wordlists/en.txt").split_whitespace().map(|s| s.into()).collect() };
}

/// An error that might occur during mnemonic decoding
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    /// Invalid word encountered
    BadWord(String),
    /// Checksum was not correct (expected, actual)
    BadChecksum(u8, u8),
    /// The number of words was invalid
    InvalidLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BadWord(ref b) => write!(f, "invalid bip39 word {}", b),
            Error::BadChecksum(exp, actual) => write!(f, "checksum 0x{:x} does not match expected 0x{:x}", actual, exp),
            Error::InvalidLength(ell) => write!(f, "invalid mnemonic length {}", ell),
        }
    }
}

/// Returns the index of a word in the wordlist
pub fn search(word: &str) -> Result<u16, Error> {
	
    let w = word.to_string();
	match WORDS.binary_search(&w) {
		Ok(index) => Ok(index as u16),
		Err(_) => Err(Error::BadWord(w))	
	}
}

/// Returns entropy if the mnemonic is valid else an error
pub fn validate(mnemonic: &str) -> Result<Vec<u8>, Error> {

	let words :Vec<String> = mnemonic.split_whitespace().map(|s| s.into()).collect();
    
    let sizes: [usize; 5] = [12, 15, 18, 21, 24];
    if !sizes.contains(&words.len()) {
        return Err(Error::InvalidLength(words.len()));
    }

    let mut indexes :Vec<u16> = try!(words.iter().map(|x| search(x)).collect()); // u11 vector of indexes for each word
    let checksum_bits = words.len() / 3;
    let mask = ((1 << checksum_bits) - 1) as u8;
    let last = indexes.pop().unwrap();
    let checksum = (last as u8) & mask;

    let datalen = ((11 * words.len()) - checksum_bits) / 8 - 1;
    let mut entropy :Vec<u8> = vec![0; datalen];
    entropy.push((last >> checksum_bits) as u8) ; // set the last byte to the data part of the last word
    let mut loc :usize = 11 - checksum_bits; // start setting bits from this index

    // cast vector of u11 as u8
    for index in indexes.iter().rev() {
        for i in 0..11 {
            let bit = index & (1 << i) != 0;
            entropy[datalen - loc/8] |= (bit as u8) << loc%8;
            loc += 1;
        }
    }


    let mut hash = [0; 32];
    let mut sha2 = Sha256::new();
    sha2.input(&entropy.clone());
    sha2.result(&mut hash);

    let actual = (hash[0] >> 8 - checksum_bits) & mask;
  
    if actual != checksum {
        return Err(Error::BadChecksum(checksum, actual));
    }

    Ok(entropy)
}


/// Convert mnemonic to a seed
pub fn seed<'a, T: 'a>(mnemonic: &str, passphrase: T) -> Result<[u8; 64], Error>
    where Option<&'a str>: From<T> {
        try!(validate(mnemonic));

        let salt = ("mnemonic".to_owned() + Option::from(passphrase).unwrap_or("")).into_bytes();
        let data = mnemonic.as_bytes();
        let mut seed = [0; 64];
        let mut mac = Hmac::new(Sha512::new(), &data);
        pbkdf2(&mut mac, &salt[..], 2048, &mut seed);

        Ok(seed)
    }
