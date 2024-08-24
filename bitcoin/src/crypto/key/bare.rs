//! Key types that don't carry metadata such as compressedness.
//!
//! These key types are basic wrappers around the `secp256k1` types that allow the crate to be
//! stable but they don't commit to many features. If you need additional operations you can
//! opt-in to instability by depending on the `bitcoin` crate. This way multiple libraries can
//! share the types without breaking each-other.
//!
//! The crate also doesn't force usage of `secp256k1` library specifically, so you can use it with
//! e.g. `secp256k1-zkp`. However the default API will be very limited and you'll have to implement
//! all operations on your own. Also the "magic conversions" will be always slow.

use core::fmt;

/// A basic public key containing both X and Y coordinate.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PublicKey(UncompressedStorage);

#[cfg(feature = "secp256k1")]
type UncompressedStorage = secp256k1::PublicKey;

#[cfg(not(feature = "secp256k1"))]
type UncompressedStorage = [u8; 64];

impl PublicKey {
    /// Constructs `PublicKey` using a pre-validated byte array.
    ///
    /// This is a low-level method that should be only used when linking `libsecp256k1` is
    /// undesirable. It is proactively marked `unsafe` to allow optimizing its internals based on
    /// the assumption that the input is valid. However the implementation may still choose to
    /// panic on invalid inputs rather than triggering UB.
    ///
    /// # Safety
    ///
    /// The bytes must begin with `0x04` and encode a valid point on the secp256k1 curve.
    /// The point is always uncompressed. The encoding is always big endian.
    pub unsafe fn deserialize_uncompressed_assume_valid(bytes: [u8; 65]) -> Self {
        #[cfg(feature = "secp256k1")]
        {
            Self::deserialize(&bytes).expect("validity guaranteed by the caller")
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            debug_assert_eq!(bytes[0], 0x04);
            Self(bytes[1..65].try_into().unwrap())
        }
    }

    /// Serializes self as uncompressed.
    ///
    /// This function always returns the bytes that were passed to
    /// `deserialize_uncompressed_assume_valid` (unless UB was triggered).
    pub fn serialize_uncompressed(self) -> [u8; 65] {
        #[cfg(feature = "secp256k1")]
        {
            self.0.serialize_uncompressed()
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            let mut buf = internals::array_vec::ArrayVec::<u8, 65>::new();
            buf.push(0x04); // one byte
            buf.extend_from_slice(&self.0); // len is 64
            buf.as_slice().try_into().expect("we've pushed exactly 1 + 64 == 65 bytes")
        }
    }
}

#[cfg(feature = "secp256k1")]
impl PublicKey {
    /// Serializes the public key as compressed.
    pub fn serialize(self) -> [u8; 33] {
        self.0.serialize()
    }

    /// Deserializes any kind of public key (compressed or uncompressed).
    ///
    /// The format consists of a one-byte prefix denoting the key type followed by the ponit
    /// corrdinate(s):
    /// * Prefix `0x02` - compressed format, the 32 bytes of X coordinate follow, the Y coordinate
    ///   is computed to have even parity.
    /// * Prefix `0x03` - compressed format, the 32 bytes of X coordinate follow, the Y coordinate
    ///   is computed to have odd parity.
    /// * Prefix `0x04` - uncompressed format, both X and Y coordinate follow (in that order), 32
    ///   bytes each.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PublicKeyDeserError> {
        secp256k1::PublicKey::from_slice(bytes).map(Self).map_err(PublicKeyDeserError)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "secp256k1")]
        {
            fmt::Debug::fmt(&self.0, f)
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            use hex::DisplayHex;
            fmt::Debug::fmt(&self.0.as_hex(), f)
        }
    }
}

/// An error returned when deserializing a [`PublicKey`] from bytes fails.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "secp256k1")]
pub struct PublicKeyDeserError(secp256k1::Error);

#[cfg(feature = "secp256k1")]
impl fmt::Display for PublicKeyDeserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(all(feature = "secp256k1", feature = "std"))]
impl std::error::Error for PublicKeyDeserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// X-only public key - a public key that only stores the X coordinate.
///
/// The public keys in Bitcoin are points on the SECP256K1 elliptic curve. That implies having two
/// coordinates X and Y. However the Y coordinate is not really required for cryptography to work,
/// so we skip encoding it in Taproot. We use this type to denote that the key only encodes the X
/// coordinate.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct XOnlyPublicKey(XOnlyStorage);

#[cfg(feature = "secp256k1")]
type XOnlyStorage = secp256k1::XOnlyPublicKey;

#[cfg(not(feature = "secp256k1"))]
type XOnlyStorage = [u8; 32];

impl XOnlyPublicKey {
    /// Constructs `XOnlyPublicKey` using a pre-validated byte array.
    ///
    /// This is a low-level method that should be only used when linking `libsecp256k1` is
    /// undesirable. It is proactively marked `unsafe` to allow optimizing its internals based on
    /// the assumption that the input is valid. However the implementation may still choose to
    /// panic on invalid inputs rather than triggering UB.
    ///
    /// # Safety
    ///
    /// The bytes must encode the X coordinate of a point on the SECP256K1 curve. The encoding is
    /// always big endian.
    pub unsafe fn deserialize_assume_valid(bytes: [u8; 32]) -> Self {
        #[cfg(feature = "secp256k1")]
        {
            Self::deserialize(&bytes).expect("validity guaranteed by the caller")
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            Self(bytes)
        }
    }

    /// Serializes the X coordinate of the key.
    ///
    /// This function always returns the bytes that were passed to
    /// `deserialize_assume_valid` (unless UB was triggered).
    pub fn serialize(self) -> [u8; 32] {
        #[cfg(feature = "secp256k1")]
        {
            self.0.serialize()
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            self.0
        }
    }
}

#[cfg(feature = "secp256k1")]
impl XOnlyPublicKey {
    /// Deserializes the key using its X coordinate.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinate is invalid. (There's no point with such coordinate.)
    pub fn deserialize(bytes: &[u8]) -> Result<Self, XOnlyPublicKeyDeserError> {
        secp256k1::XOnlyPublicKey::from_slice(bytes).map(Self).map_err(XOnlyPublicKeyDeserError)
    }
}

impl fmt::Debug for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "secp256k1")]
        {
            fmt::Debug::fmt(&self.0, f)
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            use hex::DisplayHex;
            fmt::Debug::fmt(&self.0.as_hex(), f)
        }
    }
}

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "secp256k1")]
        {
            fmt::Display::fmt(&self.0, f)
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            use hex::DisplayHex;
            fmt::Display::fmt(&self.0.as_hex(), f)
        }
    }
}

#[cfg(all(feature = "secp256k1", feature = "std"))]
impl std::error::Error for XOnlyPublicKeyDeserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "secp256k1")]
        {
            fmt::LowerHex::fmt(&self.0, f)
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            use hex::DisplayHex;
            fmt::LowerHex::fmt(&self.0.as_hex(), f)
        }
    }
}

/// An error returned when deserializing a [`XOnlyPublicKey`] from bytes fails.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "secp256k1")]
pub struct XOnlyPublicKeyDeserError(secp256k1::Error);

#[cfg(feature = "secp256k1")]
impl fmt::Display for XOnlyPublicKeyDeserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A private key - 32 secret bytes required to sign a transaction (message).
///
/// The bitcoin private keys are represented mostly as an ordinary array of 32 bytes, though they
/// still have some invariants protected by this type.
#[derive(Clone, Copy)]
pub struct PrivateKey(PrivKeyStorage);

#[cfg(feature = "secp256k1")]
type PrivKeyStorage = secp256k1::SecretKey;

#[cfg(not(feature = "secp256k1"))]
type PrivKeyStorage = [u8; 32];


impl PrivateKey {
    /// Constructs `PrivateKey` using a pre-validated byte array.
    ///
    /// This is a low-level method that should be only used when linking `libsecp256k1` is
    /// undesirable. It is proactively marked `unsafe` to allow optimizing its internals based on
    /// the assumption that the input is valid. However the implementation may still choose to
    /// panic on invalid inputs rather than triggering UB.
    ///
    /// # Safety
    ///
    /// The bytes must encode a valid non-zero SECP256K1 scalar lower than the order of the curve.
    /// The encoding is always big endian.
    pub unsafe fn deserialize_assume_valid(bytes: [u8; 32]) -> Self {
        #[cfg(feature = "secp256k1")]
        {
            Self::deserialize(bytes).expect("validity guaranteed by the caller")
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            Self(bytes)
        }
    }

    /// Serializes the secret key bytes.
    ///
    /// This simply returns the secret bytes passed in.
    pub fn serialize(self) -> [u8; 32] {
        #[cfg(feature = "secp256k1")]
        {
            self.0.secret_bytes()
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            self.0
        }
    }

    /// Serializes the X coordinate of the key.
    ///
    /// This function always returns the bytes that were passed to
    /// `deserialize_assume_valid` (unless UB was triggered).
    #[cfg(feature = "secp256k1")]
    pub fn deserialize(bytes: [u8; 32]) -> Result<Self, PrivateKeyDeserError> {
        secp256k1::SecretKey::from_slice(&bytes).map(Self).map_err(PrivateKeyDeserError)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "secp256k1")]
        {
            fmt::Debug::fmt(&self.0, f)
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            use hex::DisplayHex;
            let hash = hashes::sha256::Hash::hash(&self.0);
            write!(f, "{:.16}", hash)
        }
    }
}

impl Eq for PrivateKey {}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "secp256k1")]
        {
            self.0 == other.0
        }
        #[cfg(not(feature = "secp256k1"))]
        {
        todo!()
        }
    }
}

#[cfg(feature = "secp256k1")]
impl From<PublicKey> for XOnlyPublicKey {
    fn from(key: PublicKey) -> Self {
        Self(key.0.into())
    }
}

/// An error returned when deserializing a [`PrivateKey`] from bytes fails.
#[cfg(feature = "secp256k1")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyDeserError(pub(super) secp256k1::Error);

#[cfg(feature = "secp256k1")]
impl fmt::Display for PrivateKeyDeserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(all(feature = "secp256k1", feature = "std"))]
impl std::error::Error for PrivateKeyDeserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Implements conversions between types in this crate and unstable types from `secp256k1`.
///
/// **Only the helper extension trait in `bitcoin` should use this trait, do not use it yourself!**
///
/// We plan to remove this trait with semver trick once `secp256k1` is stable and its types are
/// public within this crate. That means `keys` 1.x will depend on `keys` 2.0 and reexport
/// everything plus add the trait using the public field. The version 2.0 will NOT contain the
/// trait. This way all the crates will stay perfectly compatible with all types being
/// interchangeable except for this trait.
///
/// This implements opportunistically efficient conversions: if the caller and this library use the
/// same version of `secp256k1` the operations will be no-op after all optimizations. If the
/// versions are different the conversion will happen by serializing and then deserializing the
/// value.
#[doc(hidden)]
#[cfg(feature = "secp256k1")]
pub trait UnstableConversions: Sized + sealed::Sealed {
    /// A byte array that can hold the serialized version of the key.
    type Bytes;

    /// Converts `self` to a potentially-unstable type from `secp256k1`.
    ///
    /// The closure `f` is a fallback for when the direct conversion fails. It accepts serialized
    /// bytes and returns deserialized `T`. The implementor MUST guarantee validity of the passed
    /// bytes so that the closure may simply `unwrap` the result.
    ///
    /// # Panics
    ///
    /// The closure and thus the function panics it the implementor passes invalid bytes to the
    /// closure.
    fn to_unstable<T: 'static + Copy>(self, f: impl Fn(Self::Bytes) -> T) -> T;

    /// Converts potentially-unstable `key` from `secp256k1` to `Self`.
    ///
    /// The closure `f` is a fallback for when the direct conversion fails. It accepts the value
    /// which is the `key` and returns it serialized. The caller MUST guarantee validity of the
    /// returned bytes.
    ///
    /// # Panics
    ///
    /// The function panics it the closure returns invalid bytes.
    fn from_unstable<T: 'static + Copy>(key: T, f: impl Fn(T) -> Self::Bytes) -> Self;
}

#[cfg(feature = "secp256k1")]
impl sealed::Sealed for PublicKey {}
#[cfg(feature = "secp256k1")]
impl UnstableConversions for PublicKey {
    type Bytes = [u8; 65];

    #[inline]
    fn to_unstable<T: 'static + Copy>(self, f: impl Fn(Self::Bytes) -> T) -> T {
        use core::any::Any;
        match (&self.0 as &dyn Any).downcast_ref() {
            Some(same) => *same,
            None => f(self.0.serialize_uncompressed()),
        }
    }

    #[inline]
    fn from_unstable<T: 'static + Copy>(key: T, f: impl Fn(T) -> Self::Bytes) -> Self {
        use core::any::Any;
        match (&key as &dyn Any).downcast_ref() {
            Some(same) => Self(*same),
            None => Self::deserialize(&f(key)).unwrap(),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl sealed::Sealed for XOnlyPublicKey {}
#[cfg(feature = "secp256k1")]
impl UnstableConversions for XOnlyPublicKey {
    type Bytes = [u8; 32];

    #[inline]
    fn to_unstable<T: 'static + Copy>(self, f: impl Fn(Self::Bytes) -> T) -> T {
        use core::any::Any;
        match (&self.0 as &dyn Any).downcast_ref() {
            Some(same) => *same,
            None => f(self.0.serialize()),
        }
    }

    #[inline]
    fn from_unstable<T: 'static + Copy>(key: T, f: impl Fn(T) -> Self::Bytes) -> Self {
        use core::any::Any;
        match (&key as &dyn Any).downcast_ref() {
            Some(same) => Self(*same),
            None => Self::deserialize(&f(key)).unwrap(),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl sealed::Sealed for PrivateKey {}
#[cfg(feature = "secp256k1")]
impl UnstableConversions for PrivateKey {
    type Bytes = [u8; 32];

    #[inline]
    fn to_unstable<T: 'static + Copy>(self, f: impl Fn(Self::Bytes) -> T) -> T {
        use core::any::Any;
        match (&self.0 as &dyn Any).downcast_ref() {
            Some(same) => *same,
            None => f(self.0.secret_bytes()),
        }
    }

    #[inline]
    fn from_unstable<T: 'static + Copy>(key: T, f: impl Fn(T) -> Self::Bytes) -> Self {
        use core::any::Any;
        match (&key as &dyn Any).downcast_ref() {
            Some(same) => Self(*same),
            None => Self::deserialize(f(key)).unwrap(),
        }
    }
}

#[cfg(feature = "secp256k1")]
mod sealed {
    #[doc(hidden)]
    pub trait Sealed {}
}
