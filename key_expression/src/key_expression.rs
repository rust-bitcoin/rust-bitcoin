// SPDX-License-Identifier: CC0-1.0

//! Key expressions for output descriptors, as defined in [BIP-0380].
//!
//! This module handles keys and their origins, not descriptor scripts or checksums. Origin
//! metadata uses [`crate::bip32::KeyOrigin`].
//!
//! [BIP-0380]: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>

use core::fmt;
use core::str::FromStr;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use crypto::key::LegacyPublicKey;
use crypto::secp256k1::XOnlyPublicKey;

use crate::bip32::{KeyOrigin, RelativeDerivationPath};

#[rustfmt::skip] // Keep the public re-export separate.
#[doc(no_inline)]
pub use self::error::ParsePublicKeyExpressionError;

/// A single public key with optional origin information.
///
/// Supports compressed and uncompressed public keys from [BIP-0380] and the x-only key form
/// from [BIP-0386]. It does not accept extended keys, secret keys, derivation suffixes, or
/// descriptor syntax. Descriptor consumers enforce script-specific rules on these keys.
///
/// An origin is written before the key as `[fingerprint]` or `[fingerprint/path]`. Origin
/// steps use decimal indices with `h` or `'` for hardening. Display uses lowercase hex and
/// `'` for hardened steps. With `serde`, both human-readable and binary formats use this
/// canonical string.
///
/// # Examples
///
/// The example uses the secp256k1 generator from [SEC 2 §2.4.1] and a synthetic origin.
///
/// ```
/// use bitcoin_key_expression::key_expression::{ParsePublicKeyExpressionError, PublicKeyExpression};
///
/// let key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// let expression: PublicKeyExpression = format!("[d34db33f/84h/0/1]{key_hex}").parse()?;
/// let PublicKeyExpression::Full { key, origin: Some(origin) } = &expression else {
///     panic!("expected a full public key with an origin");
/// };
/// assert!(key.compressed());
/// assert_eq!(origin.fingerprint.to_string(), "d34db33f");
/// assert_eq!(expression.to_string(), format!("[d34db33f/84'/0/1]{key_hex}"));
/// # Ok::<(), ParsePublicKeyExpressionError>(())
/// ```
///
/// [BIP-0380]: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>
/// [BIP-0386]: <https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki>
/// [SEC 2 §2.4.1]: <https://www.secg.org/sec2-v2.pdf#page=13>
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublicKeyExpression {
    /// A compressed or uncompressed public key.
    Full {
        /// The public key, including its compressedness.
        key: LegacyPublicKey,
        /// The claimed derivation origin, if provided.
        origin: Option<KeyOrigin>,
    },
    /// An x-only public key, without a parity bit.
    XOnly {
        /// The x-only public key.
        key: XOnlyPublicKey,
        /// The claimed derivation origin, if provided.
        origin: Option<KeyOrigin>,
    },
}

impl PublicKeyExpression {
    /// Returns the claimed derivation origin, if provided.
    pub fn origin(&self) -> Option<&KeyOrigin> {
        match self {
            Self::Full { origin, .. } | Self::XOnly { origin, .. } => origin.as_ref(),
        }
    }
}

impl FromStr for PublicKeyExpression {
    type Err = ParsePublicKeyExpressionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ParsePublicKeyExpressionError as Error;

        let (origin, key) = match s.strip_prefix('[') {
            Some(s) => {
                let (origin, key) = s.split_once(']').ok_or(Error::InvalidOrigin)?;
                if origin.contains('[') || key.contains(['[', ']']) {
                    return Err(Error::InvalidOrigin);
                }
                let (fingerprint, path) = match origin.split_once('/') {
                    Some((fingerprint, path)) => (fingerprint, Some(path)),
                    None => (origin, None),
                };
                let fingerprint = fingerprint.parse().map_err(|_| Error::InvalidFingerprint)?;
                let path = match path {
                    Some(path) => path
                        .split('/')
                        .map(|step| {
                            if step.starts_with('+') {
                                return Err(Error::InvalidOriginPath);
                            }
                            step.parse().map_err(|_| Error::InvalidOriginPath)
                        })
                        .collect::<Result<_, _>>()?,
                    None => RelativeDerivationPath::default(),
                };
                (Some(KeyOrigin { fingerprint, path }), key)
            }
            None if s.contains(['[', ']']) => return Err(Error::InvalidOrigin),
            None => (None, s),
        };

        match key.len() {
            0 => Err(Error::MissingKey),
            64 => key
                .parse()
                .map(|key| Self::XOnly { key, origin })
                .map_err(|_| Error::InvalidPublicKey),
            66 | 130 => key
                .parse()
                .map(|key| Self::Full { key, origin })
                .map_err(|_| Error::InvalidPublicKey),
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

impl fmt::Display for PublicKeyExpression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(origin) = self.origin() {
            write!(f, "[{}", origin.fingerprint)?;
            if !origin.path.is_empty() {
                write!(f, "/{}", origin.path)?;
            }
            f.write_str("]")?;
        }
        match self {
            Self::Full { key, .. } => fmt::Display::fmt(key, f),
            Self::XOnly { key, .. } => fmt::Display::fmt(key, f),
        }
    }
}

#[cfg(feature = "serde")]
internals::serde_string_impl!(PublicKeyExpression, "a single public-key expression");

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for PublicKeyExpression {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let x_only = u.arbitrary()?;
        let origin = u.arbitrary()?;
        if x_only {
            Ok(Self::XOnly { key: u.arbitrary()?, origin })
        } else {
            let key: LegacyPublicKey = u.arbitrary()?;
            Ok(Self::Full { key: key.with_compressedness(u.arbitrary()?), origin })
        }
    }
}

/// Errors parsing key expressions.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    /// Error parsing a single public-key expression.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ParsePublicKeyExpressionError {
        /// The key origin has malformed brackets or appears more than once.
        InvalidOrigin,
        /// The fingerprint is not exactly eight hexadecimal characters.
        InvalidFingerprint,
        /// The origin path is not a sequence of valid child numbers.
        InvalidOriginPath,
        /// No public key was provided.
        MissingKey,
        /// The key is not a valid compressed, uncompressed, or x-only public key in hex.
        InvalidPublicKey,
    }

    impl From<Infallible> for ParsePublicKeyExpressionError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParsePublicKeyExpressionError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::InvalidOrigin
                | Self::InvalidFingerprint
                | Self::InvalidOriginPath
                | Self::MissingKey
                | Self::InvalidPublicKey => None,
            }
        }
    }

    impl fmt::Display for ParsePublicKeyExpressionError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::InvalidOrigin => f.write_str("malformed or repeated key origin"),
                Self::InvalidFingerprint =>
                    f.write_str("key origin fingerprint must be eight hexadecimal characters"),
                Self::InvalidOriginPath => f.write_str("invalid key origin derivation path"),
                Self::MissingKey => f.write_str("missing public key"),
                Self::InvalidPublicKey => f.write_str("invalid public key encoding"),
            }
        }
    }
}
