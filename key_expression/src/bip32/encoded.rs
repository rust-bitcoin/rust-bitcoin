// SPDX-License-Identifier: CC0-1.0

use core::fmt;
use core::str::FromStr;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use crypto::secp256k1;

use super::{
    encode_xkey_header, private_key_payload, ChainCode, ChildNumber, DecodedXkey,
    EncodedXprivDecodeError, EncodedXpubDecodeError, Fingerprint, ParseEncodedXprivError,
    ParseEncodedXpubError, UnknownXkeyVersionError, Xpriv, Xpub,
};

/// An extended private key with uninterpreted version bytes.
///
/// The payload follows BIP-0032. Only the two standard private-key versions can be converted to
/// [`Xpriv`]. This type does not infer a network or script policy from other versions.
///
/// `Debug` redacts the private key. Display, binary encoding, and string serde expose it, just
/// as they do with [`Xpriv`].
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct EncodedXpriv {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: Fingerprint,
    child_number: ChildNumber,
    chain_code: ChainCode,
    private_key: secp256k1::SecretKey,
}

impl EncodedXpriv {
    /// Decodes a 78-byte extended private key without interpreting the version bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if master metadata is invalid, the private-key prefix is not zero, or
    /// the scalar is invalid.
    pub fn from_byte_array(data: &[u8; 78]) -> Result<Self, EncodedXprivDecodeError> {
        let DecodedXkey { version, depth, parent_fingerprint, child_number, chain_code, key_bytes } =
            DecodedXkey::decode(data).map_err(EncodedXprivDecodeError::Xkey)?;
        let private_key = private_key_payload(key_bytes)
            .ok_or(EncodedXprivDecodeError::InvalidPrivateKeyPrefix)?;
        Ok(Self {
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            private_key: secp256k1::SecretKey::from_secret_bytes(*private_key)
                .map_err(EncodedXprivDecodeError::Secp256k1)?,
        })
    }

    /// Returns the four version bytes in wire order.
    pub fn version_bytes(&self) -> [u8; 4] { self.version }

    /// Returns the 78-byte encoding, including the private key and original version bytes.
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = encode_xkey_header(
            self.version,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
        );
        ret[46..78].copy_from_slice(self.private_key.as_secret_bytes());
        ret
    }
}

impl From<Xpriv> for EncodedXpriv {
    fn from(key: Xpriv) -> Self {
        Self {
            version: key.version_bytes(),
            depth: key.depth,
            parent_fingerprint: key.parent_fingerprint,
            child_number: key.child_number,
            chain_code: key.chain_code,
            private_key: key.private_key,
        }
    }
}

impl TryFrom<EncodedXpriv> for Xpriv {
    type Error = UnknownXkeyVersionError;

    fn try_from(key: EncodedXpriv) -> Result<Self, Self::Error> {
        let network = Self::network_from_version(key.version)
            .ok_or_else(|| UnknownXkeyVersionError::new(key.version))?;
        Ok(Self {
            network,
            depth: key.depth,
            parent_fingerprint: key.parent_fingerprint,
            child_number: key.child_number,
            chain_code: key.chain_code,
            private_key: key.private_key,
        })
    }
}

impl fmt::Debug for EncodedXpriv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EncodedXpriv")
            .field("version", &self.version)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("private_key", &"[SecretKey]")
            .finish()
    }
}

impl fmt::Display for EncodedXpriv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base58::Base58CkString::encode(&self.encode())
            .expect("78 bytes encode to less than the length limit")
            .fmt(f)
    }
}

impl FromStr for EncodedXpriv {
    type Err = ParseEncodedXprivError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = base58::decode_check_to_array::<78>(s).map_err(Self::Err::Base58)?;
        Self::from_byte_array(&data).map_err(Self::Err::Decode)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "serde")]
internals::serde_string_impl!(EncodedXpriv, "a version-preserving extended private key");

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EncodedXpriv {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut key = Self::from(u.arbitrary::<Xpriv>()?);
        key.version = u.arbitrary()?;
        Ok(key)
    }
}

/// An extended public key with uninterpreted version bytes.
///
/// The payload follows BIP-0032. Only the two standard public-key versions can be converted to
/// [`Xpub`]. This type does not infer a network or script policy from other versions.
///
/// # Examples
///
/// ```
/// use bitcoin_key_expression::bip32::{EncodedXpub, Xpub};
///
/// let xpub: Xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8".parse().unwrap();
/// let mut bytes = xpub.encode();
/// let version = [0x12, 0x34, 0x56, 0x78];
/// bytes[..4].copy_from_slice(&version);
/// let encoded = EncodedXpub::from_byte_array(&bytes).unwrap();
/// assert_eq!(encoded.version_bytes(), version);
/// assert_eq!(encoded.encode(), bytes);
/// assert_eq!(Xpub::try_from(encoded).unwrap_err().version_bytes(), version);
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct EncodedXpub {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: Fingerprint,
    child_number: ChildNumber,
    chain_code: ChainCode,
    public_key: secp256k1::PublicKey,
}

impl EncodedXpub {
    /// Decodes a 78-byte extended public key without interpreting the version bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if master metadata is invalid or the key is not a valid compressed
    /// public key.
    pub fn from_byte_array(data: &[u8; 78]) -> Result<Self, EncodedXpubDecodeError> {
        let DecodedXkey { version, depth, parent_fingerprint, child_number, chain_code, key_bytes } =
            DecodedXkey::decode(data).map_err(EncodedXpubDecodeError::Xkey)?;
        Ok(Self {
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key: secp256k1::PublicKey::from_slice(key_bytes)
                .map_err(EncodedXpubDecodeError::Secp256k1)?,
        })
    }

    /// Returns the four version bytes in wire order.
    pub fn version_bytes(&self) -> [u8; 4] { self.version }

    /// Returns the 78-byte encoding, including the original version bytes.
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = encode_xkey_header(
            self.version,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
        );
        ret[45..78].copy_from_slice(&self.public_key.serialize());
        ret
    }
}

impl From<Xpub> for EncodedXpub {
    fn from(key: Xpub) -> Self {
        Self {
            version: key.version_bytes(),
            depth: key.depth,
            parent_fingerprint: key.parent_fingerprint,
            child_number: key.child_number,
            chain_code: key.chain_code,
            public_key: key.public_key,
        }
    }
}

impl TryFrom<EncodedXpub> for Xpub {
    type Error = UnknownXkeyVersionError;

    fn try_from(key: EncodedXpub) -> Result<Self, Self::Error> {
        let network = Self::network_from_version(key.version)
            .ok_or_else(|| UnknownXkeyVersionError::new(key.version))?;
        Ok(Self {
            network,
            depth: key.depth,
            parent_fingerprint: key.parent_fingerprint,
            child_number: key.child_number,
            chain_code: key.chain_code,
            public_key: key.public_key,
        })
    }
}

impl fmt::Display for EncodedXpub {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base58::Base58CkString::encode(&self.encode())
            .expect("78 bytes encode to less than the length limit")
            .fmt(f)
    }
}

impl FromStr for EncodedXpub {
    type Err = ParseEncodedXpubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = base58::decode_check_to_array::<78>(s).map_err(Self::Err::Base58)?;
        Self::from_byte_array(&data).map_err(Self::Err::Decode)
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "serde")]
internals::serde_string_impl!(EncodedXpub, "a version-preserving extended public key");

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EncodedXpub {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut key = Self::from(u.arbitrary::<Xpub>()?);
        key.version = u.arbitrary()?;
        Ok(key)
    }
}
