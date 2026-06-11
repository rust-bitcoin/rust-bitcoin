// SPDX-License-Identifier: CC0-1.0

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ByteVecDecoder, DecoderStatus};

use super::{Script, ScriptBufDecoderError, P2A_PROGRAM};
use crate::opcodes::all::{OP_1, OP_1NEGATE, OP_EQUAL, OP_HASH160};
use crate::opcodes::{self, Opcode};
use crate::prelude::{Box, Vec};
use crate::script::{Builder, PushBytes, ScriptHash, WScriptHash};
use crate::witness_version::WitnessVersion;
use crate::ScriptPubKeyBuf;

/// An owned, growable script.
///
/// `ScriptBuf` is the most common script type that has the ownership over the contents of the
/// script. It has a close relationship with its borrowed counterpart, [`Script`].
///
/// Just as other similar types, this implements [`Deref`], so [deref coercions] apply. Also note
/// that all the safety/validity restrictions that apply to [`Script`] apply to `ScriptBuf` as well.
///
/// # Hexadecimal strings
///
/// Scripts are consensus encoded with a length prefix and as a result of this in some places in the
/// ecosystem one will encounter hex strings that include the prefix while in other places the
/// prefix is excluded. To support parsing and formatting scripts as hex we provide a bunch of
/// different APIs and trait implementations. Please see [`examples/script.rs`] for a thorough
/// example of all the APIs.
///
/// [`examples/script.rs`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/script.rs>
/// [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
///
/// # Panics
///
/// `ScriptBuf` is backed by [`Vec`] and inherits its panic behavior. This means that attempting to
/// construct scripts larger than `isize::MAX` bytes will panic.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ScriptBuf<T>(PhantomData<T>, Vec<u8>);

impl<T> ScriptBuf<T> {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self { Self::from_bytes(Vec::new()) }

    /// Converts byte vector into script.
    ///
    /// This method doesn't (re)allocate. `bytes` is just the script bytes **not** consensus
    /// encoding (i.e no length prefix).
    #[inline]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self { Self(PhantomData, bytes) }

    /// Constructs a new [`ScriptBuf`] from a hex string.
    ///
    /// The input string is expected to be consensus encoded i.e., includes the length prefix.
    ///
    /// # Errors
    ///
    /// * If `s` cannot be parsed into a vector.
    /// * If the parsed bytes cannot be decoded as a valid script (incl. the length prefix).
    #[cfg(feature = "hex")]
    pub fn from_hex_prefixed(
        s: &str,
    ) -> Result<Self, encoding::FromHexError<ScriptBufDecoderError>> {
        encoding::decode_from_hex(s)
    }

    /// Constructs a new [`ScriptBuf`] from a hex string.
    ///
    /// This is **not** consensus encoding. If your hex string is a consensus encoded script
    /// then use `ScriptBuf::from_hex_prefixed`.
    ///
    /// There is no script decoding error path because what ever is in the hex input string is
    /// assumed to be the script. This means if you pass a consensus encoded hex string into this
    /// function there will be no error and the script will not be what you expect.
    ///
    /// # Errors
    ///
    /// Errors if `s` cannot be parsed into a vector.
    #[cfg(feature = "hex")]
    pub fn from_hex_no_length_prefix(s: &str) -> Result<Self, hex::DecodeVariableLengthBytesError> {
        let v = hex::decode_to_vec(s)?;
        Ok(Self::from_bytes(v))
    }

    /// Returns a reference to unsized script.
    #[inline]
    pub fn as_script(&self) -> &Script<T> { Script::from_bytes(&self.1) }

    /// Returns a mutable reference to unsized script.
    #[inline]
    pub fn as_mut_script(&mut self) -> &mut Script<T> { Script::from_bytes_mut(&mut self.1) }

    /// Converts the script into a byte vector.
    ///
    /// This method doesn't (re)allocate.
    ///
    /// # Returns
    ///
    /// Just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> { self.1 }

    /// Converts this `ScriptBuf` into a [boxed](Box) [`Script`].
    ///
    /// This method reallocates if the capacity is greater than length of the script but should not
    /// when they are equal. If you know beforehand that you need to create a script of exact size
    /// use [`reserve_exact`](Self::reserve_exact) before adding data to the script so that the
    /// reallocation can be avoided.
    #[must_use]
    #[inline]
    pub fn into_boxed_script(self) -> Box<Script<T>> {
        Script::from_boxed_bytes(self.into_bytes().into_boxed_slice())
    }

    /// Constructs a new empty script with at least the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self { Self::from_bytes(Vec::with_capacity(capacity)) }

    /// Pre-allocates at least `additional_len` bytes if needed.
    ///
    /// Reserves capacity for at least `additional_len` more bytes to be inserted in the given
    /// script. The script may reserve more space to speculatively avoid frequent reallocations.
    /// After calling `reserve`, capacity will be greater than or equal to
    /// `self.len() + additional_len`. Does nothing if capacity is already sufficient.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX` bytes.
    #[inline]
    pub fn reserve(&mut self, additional_len: usize) { self.1.reserve(additional_len); }

    /// Pre-allocates exactly `additional_len` bytes if needed.
    ///
    /// Unlike `reserve`, this will not deliberately over-allocate to speculatively avoid frequent
    /// allocations. After calling `reserve_exact`, capacity will be greater than or equal to
    /// `self.len() + additional`. Does nothing if the capacity is already sufficient.
    ///
    /// Note that the allocator may give the collection more space than it requests. Therefore,
    /// capacity cannot be relied upon to be precisely minimal. Prefer [`reserve`](Self::reserve)
    /// if future insertions are expected.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX` bytes.
    #[inline]
    pub fn reserve_exact(&mut self, additional_len: usize) { self.1.reserve_exact(additional_len); }

    /// Returns the number of **bytes** available for writing without reallocation.
    ///
    /// It is guaranteed that `script.capacity() >= script.len()` always holds.
    #[inline]
    pub fn capacity(&self) -> usize { self.1.capacity() }

    /// Gets the hex representation of this script.
    ///
    /// # Returns
    ///
    /// Just the script bytes in hexadecimal **not** consensus encoding of the script i.e., the
    /// string will not include a length prefix.
    #[cfg(feature = "hex")]
    #[inline]
    #[deprecated(since = "1.0.0-rc.0", note = "use `format!(\"{var:x}\")` instead")]
    pub fn to_hex(&self) -> alloc::string::String { alloc::format!("{:x}", self) }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, data: Opcode) { self.as_byte_vec().push(data.to_u8()); }

    /// Adds instructions to push some arbitrary data onto the stack.
    ///
    /// If the data can be exactly produced by a numeric opcode, that opcode
    /// will be used, since its behavior is equivalent but will not violate minimality
    /// rules. To avoid this, use [`ScriptBuf::push_slice_non_minimal`] which will always
    /// use a push opcode.
    ///
    /// However, this method does *not* enforce any numeric minimality rules.
    /// If your pushes should be interpreted as numbers, ensure your input does
    /// not have any leading zeros. In particular, the number 0 should be encoded
    /// as an empty string rather than as a single 0 byte.
    pub fn push_slice<D: AsRef<PushBytes>>(&mut self, data: D) {
        let bytes = data.as_ref().as_bytes();
        if bytes.len() == 1 {
            match bytes[0] {
                0x81 => {
                    self.push_opcode(OP_1NEGATE);
                }
                1..=16 => {
                    self.push_opcode(Opcode::from(bytes[0] + (OP_1.to_u8() - 1)));
                }
                _ => {
                    self.push_slice_non_minimal(data);
                }
            }
        } else {
            self.push_slice_non_minimal(data);
        }
    }

    /// Adds instructions to push some arbitrary data onto the stack without minimality.
    ///
    /// Standardness rules require push minimality according to [CheckMinimalPush] of core.
    ///
    /// [CheckMinimalPush]: <https://github.com/bitcoin/bitcoin/blob/99a4ddf5ab1b3e514d08b90ad8565827fda7b63b/src/script/script.cpp#L366>
    pub fn push_slice_non_minimal<D: AsRef<PushBytes>>(&mut self, data: D) {
        let data = data.as_ref();
        self.reserve(Self::reserved_len_for_slice(data.len()));
        self.push_slice_no_opt(data);
    }

    /// Computes the sum of `len` and the length of an appropriate push opcode.
    fn reserved_len_for_slice(len: usize) -> usize {
        len + match len {
            0..=0x4b => 1,
            0x4c..=0xff => 2,
            0x100..=0xffff => 3,
            // we don't care about oversized, the other fn will panic anyway
            _ => 5,
        }
    }

    /// Pretends to convert `&mut ScriptBuf` to `&mut Vec<u8>` so that it can be modified.
    ///
    /// Note: if the returned value leaks the original `ScriptBuf` will become empty.
    fn as_byte_vec(&mut self) -> ScriptBufAsVec<'_, T> {
        let vec = core::mem::take(self).into_bytes();
        ScriptBufAsVec(self, vec)
    }

    /// Pushes the slice without reserving
    fn push_slice_no_opt(&mut self, data: &PushBytes) {
        let mut this = self.as_byte_vec();
        // Start with a PUSH opcode
        match data.len() as u64 {
            n if n < opcodes::OP_PUSHDATA1.into() => {
                this.push(n as u8);
            }
            n if n < 0x100 => {
                this.push(opcodes::OP_PUSHDATA1);
                this.push(n as u8);
            }
            n if n < 0x10000 => {
                this.push(opcodes::OP_PUSHDATA2);
                this.push((n % 0x100) as u8);
                this.push((n / 0x100) as u8);
            }
            // `PushBytes` enforces len < 0x100000000
            n => {
                this.push(opcodes::OP_PUSHDATA4);
                this.push((n % 0x100) as u8);
                this.push(((n / 0x100) % 0x100) as u8);
                this.push(((n / 0x10000) % 0x100) as u8);
                this.push((n / 0x0100_0000) as u8);
            }
        }
        // Then push the raw bytes
        this.extend_from_slice(data.as_bytes());
    }
}

impl ScriptPubKeyBuf {
    /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_p2sh(script_hash: ScriptHash) -> Self {
        Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(script_hash)
            .push_opcode(OP_EQUAL)
            .into_script()
    }

    /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_p2wsh(script_hash: WScriptHash) -> Self {
        // script hash is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
        super::new_witness_program_unchecked(WitnessVersion::V0, script_hash)
    }

    /// Generates pay to anchor output.
    pub fn new_p2a() -> Self {
        super::new_witness_program_unchecked(WitnessVersion::V1, P2A_PROGRAM)
    }
}

// Cannot derive due to generics.
impl<T> Default for ScriptBuf<T> {
    fn default() -> Self { Self(PhantomData, Vec::new()) }
}

impl<T> Deref for ScriptBuf<T> {
    type Target = Script<T>;

    #[inline]
    fn deref(&self) -> &Self::Target { self.as_script() }
}

impl<T> DerefMut for ScriptBuf<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { self.as_mut_script() }
}

impl<T> encoding::Decode for ScriptBuf<T> {
    type Decoder = ScriptBufDecoder<T>;
}

/// The decoder for the [`ScriptBuf`] type.
#[derive(Debug, Clone)]
pub struct ScriptBufDecoder<T>(ByteVecDecoder, PhantomData<T>);

impl<T> ScriptBufDecoder<T> {
    /// Constructs a new [`ScriptBuf`] decoder.
    pub const fn new() -> Self { Self(ByteVecDecoder::new(), PhantomData) }
}

impl<T> Default for ScriptBufDecoder<T> {
    fn default() -> Self { Self::new() }
}

impl<T> encoding::Decoder for ScriptBufDecoder<T> {
    type Output = ScriptBuf<T>;
    type Error = ScriptBufDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(ScriptBufDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(ScriptBuf::from_bytes(self.0.end().map_err(ScriptBufDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

/// Pretends that this is a mutable reference to [`ScriptBuf`]'s internal buffer.
///
/// In reality the backing `Vec<u8>` is swapped with an empty one and this is holding both the
/// reference and the vec. The vec is put back when this drops so it also covers panics. (But not
/// leaks, which is OK since we never leak.)
pub(crate) struct ScriptBufAsVec<'a, T>(&'a mut ScriptBuf<T>, Vec<u8>);

impl<T> core::ops::Deref for ScriptBufAsVec<'_, T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target { &self.1 }
}

impl<T> core::ops::DerefMut for ScriptBufAsVec<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.1 }
}

impl<T> Drop for ScriptBufAsVec<'_, T> {
    fn drop(&mut self) {
        let vec = core::mem::take(&mut self.1);
        *(self.0) = ScriptBuf::from_bytes(vec);
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, T> Arbitrary<'a> for ScriptBuf<T> {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = Vec::<u8>::arbitrary(u)?;
        Ok(Self::from_bytes(v))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::ScriptBuf;
    use crate::script::ScriptSigTag as Tag;

    #[test]
    fn reserved_len_for_slice() {
        // Length plus the size of the push opcode that prefixes it.
        assert_eq!(ScriptBuf::<Tag>::reserved_len_for_slice(0), 1);
        assert_eq!(ScriptBuf::<Tag>::reserved_len_for_slice(0x4b), 0x4b + 1);
        assert_eq!(ScriptBuf::<Tag>::reserved_len_for_slice(0x4c), 0x4c + 2);
        assert_eq!(ScriptBuf::<Tag>::reserved_len_for_slice(0xff), 0xff + 2);
        assert_eq!(ScriptBuf::<Tag>::reserved_len_for_slice(0x100), 0x100 + 3);
        assert_eq!(ScriptBuf::<Tag>::reserved_len_for_slice(0xffff), 0xffff + 3);
        assert_eq!(ScriptBuf::<Tag>::reserved_len_for_slice(0x10000), 0x10000 + 5);
    }

    #[test]
    fn as_byte_vec_deref_restores() {
        let mut script = ScriptBuf::<Tag>::from_bytes(vec![1, 2, 3]);
        {
            let vec = script.as_byte_vec();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec.as_slice(), &[1, 2, 3]);
        }
        assert_eq!(script.as_bytes(), &[1, 2, 3]);
    }
}
