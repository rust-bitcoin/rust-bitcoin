// SPDX-License-Identifier: CC0-1.0

use super::{
    ContextUnknownTag, RedeemScriptTag, ScriptPubkeyTag, ScriptSigTag, TapScriptTag,
    WitnessScriptTag,
};

/// An owned script with no specific known context.
pub type ScriptBuf = tmp::ScriptBuf<ContextUnknownTag>;

/// An owned, growable scriptSig.
pub type ScriptSigBuf = tmp::ScriptBuf<ScriptSigTag>;

/// An owned, growable scriptPubkey.
pub type ScriptPubkeyBuf = tmp::ScriptBuf<ScriptPubkeyTag>;

/// An owned, growable redeemScript.
pub type RedeemScriptBuf = tmp::ScriptBuf<RedeemScriptTag>;

/// An owned, growable witnessScript.
pub type WitnessScriptBuf = tmp::ScriptBuf<WitnessScriptTag>;

/// An owned, growable tapScript.
pub type TapScriptBuf = tmp::ScriptBuf<TapScriptTag>;

// TODO: This module can go away once we remove the `Script` alias. Added to make dev/review easier.
pub(in crate::script) mod tmp {
    use core::marker::PhantomData;
    use core::ops::{Deref, DerefMut};

    #[cfg(feature = "arbitrary")]
    use arbitrary::{Arbitrary, Unstructured};

    use crate::prelude::{Box, Vec};
    use crate::script::{borrowed, Context};

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
    /// eccosystem one will encounter hex strings that include the prefix while in other places the
    /// prefix is excluded. To support parsing and formatting scripts as hex we provide a bunch of
    /// different APIs and trait implementations. Please see [`examples/script.rs`] for a thorough
    /// example of all the APIs.
    ///
    /// [`examples/script.rs`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/script.rs>
    /// [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
    #[derive(Default, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
    pub struct ScriptBuf<C>(PhantomData<C>, Vec<u8>)
    where
        C: Context;

    impl<C: Context> ScriptBuf<C> {
        /// Constructs a new empty script.
        #[inline]
        pub const fn new() -> Self { Self::from_bytes(Vec::new()) }

        /// Converts byte vector into script.
        ///
        /// This method doesn't (re)allocate. `bytes` is just the script bytes **not** consensus
        /// encoding (i.e no length prefix).
        #[inline]
        pub const fn from_bytes(bytes: Vec<u8>) -> Self { Self(PhantomData, bytes) }

        /// Returns a reference to unsized script.
        #[inline]
        pub fn as_script(&self) -> &borrowed::tmp::Script<C> {
            borrowed::tmp::Script::<C>::from_bytes(&self.1)
        }

        /// Returns a mutable reference to unsized script.
        #[inline]
        pub fn as_mut_script(&mut self) -> &mut borrowed::tmp::Script<C> {
            borrowed::tmp::Script::from_bytes_mut(&mut self.1)
        }

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
        pub fn into_boxed_script(self) -> Box<borrowed::tmp::Script<C>> {
            borrowed::tmp::Script::from_boxed_bytes(self.into_bytes().into_boxed_slice())
        }

        /// Constructs a new empty script with at least the specified capacity.
        #[inline]
        pub fn with_capacity(capacity: usize) -> Self {
            ScriptBuf::from_bytes(Vec::with_capacity(capacity))
        }

        /// Pre-allocates at least `additional_len` bytes if needed.
        ///
        /// Reserves capacity for at least `additional_len` more bytes to be inserted in the given
        /// script. The script may reserve more space to speculatively avoid frequent reallocations.
        /// After calling `reserve`, capacity will be greater than or equal to
        /// `self.len() + additional_len`. Does nothing if capacity is already sufficient.
        ///
        /// # Panics
        ///
        /// Panics if the new capacity exceeds `isize::MAX bytes`.
        #[inline]
        pub fn reserve(&mut self, additional_len: usize) { self.1.reserve(additional_len); }

        /// Pre-allocates exactly `additional_len` bytes if needed.
        ///
        /// Unlike `reserve`, this will not deliberately over-allocate to speculatively avoid frequent
        /// allocations. After calling `reserve_exact`, capacity will be greater than or equal to
        /// `self.len() + additional`. Does nothing if the capacity is already sufficient.
        ///
        /// Note that the allocator may give the collection more space than it requests. Therefore,
        /// capacity can not be relied upon to be precisely minimal. Prefer [`reserve`](Self::reserve)
        /// if future insertions are expected.
        ///
        /// # Panics
        ///
        /// Panics if the new capacity exceeds `isize::MAX bytes`.
        #[inline]
        pub fn reserve_exact(&mut self, additional_len: usize) {
            self.1.reserve_exact(additional_len);
        }

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
        #[cfg(feature = "alloc")]
        #[cfg(feature = "hex")]
        #[inline]
        pub fn to_hex(&self) -> alloc::string::String { alloc::format!("{:x}", self) }
    }

    impl<C: Context> Deref for ScriptBuf<C> {
        type Target = borrowed::tmp::Script<C>;

        #[inline]
        fn deref(&self) -> &Self::Target { self.as_script() }
    }

    impl<C: Context> DerefMut for ScriptBuf<C> {
        #[inline]
        fn deref_mut(&mut self) -> &mut Self::Target { self.as_mut_script() }
    }

    #[cfg(feature = "arbitrary")]
    impl<'a, C: Context> Arbitrary<'a> for ScriptBuf<C> {
        #[inline]
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let v = Vec::<u8>::arbitrary(u)?;
            Ok(ScriptBuf::from_bytes(v))
        }
    }
}

impl ScriptPubkeyBuf {
    /// Adds context to this scriptPubkey returning a [`RedeemScriptBuf`].
    pub fn into_redeem_script(self) -> RedeemScriptBuf {
        RedeemScriptBuf::from_bytes(self.into_bytes())
    }

    /// Adds context to this scriptPubkey returning a [`WitnessScriptBuf`].
    pub fn into_witness_script(self) -> WitnessScriptBuf {
        WitnessScriptBuf::from_bytes(self.into_bytes())
    }

    /// Adds context to this scriptPubkey returning a [`TapScriptBuf`].
    pub fn into_tap_script(self) -> TapScriptBuf { TapScriptBuf::from_bytes(self.into_bytes()) }

    /// Removes context from this scriptPubkey.
    // Once script tagging is done this should not be needed.
    #[deprecated(since = "TBD", note = "once script tagging is done this should not be needed")]
    pub fn into_context_unknown(self) -> ScriptBuf { ScriptBuf::from_bytes(self.into_bytes()) }
}

impl RedeemScriptBuf {
    /// Removes context from this redeemScript returning a [`ScriptPubkeyBuf`].
    pub fn into_script_pubkey(self) -> ScriptPubkeyBuf {
        ScriptPubkeyBuf::from_bytes(self.into_bytes())
    }
}

impl WitnessScriptBuf {
    /// Removes context from this witnessScript returning a [`ScriptPubkeyBuf`].
    pub fn into_script_pubkey(self) -> ScriptPubkeyBuf {
        ScriptPubkeyBuf::from_bytes(self.into_bytes())
    }
}

impl TapScriptBuf {
    /// Removes context from this `TapScript` returning a [`ScriptPubkeyBuf`].
    pub fn into_script_pubkey(self) -> ScriptPubkeyBuf {
        ScriptPubkeyBuf::from_bytes(self.into_bytes())
    }
}

impl tmp::ScriptBuf<ContextUnknownTag> {
    /// Adds context to this script returning a [`ScriptSigBuf`].
    pub fn into_script_sig(self) -> ScriptSigBuf { ScriptSigBuf::from_bytes(self.into_bytes()) }

    /// Adds context to this script returning a [`ScriptPubkeyBuf`].
    pub fn into_script_pubkey(self) -> ScriptPubkeyBuf {
        ScriptPubkeyBuf::from_bytes(self.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_buf_from_bytes() {
        let bytes = vec![1, 2, 3];
        let script = ScriptPubkeyBuf::from_bytes(bytes.clone());
        assert_eq!(script.as_bytes(), bytes);
    }

    #[test]
    fn script_buf_as_script() {
        let bytes = vec![1, 2, 3];
        let script = ScriptPubkeyBuf::from_bytes(bytes.clone());
        let script_ref = script.as_script();
        assert_eq!(script_ref.as_bytes(), bytes);
    }

    #[test]
    fn script_buf_as_mut_script() {
        let bytes = vec![1, 2, 3];
        let mut script = ScriptPubkeyBuf::from_bytes(bytes.clone());
        let script_mut_ref = script.as_mut_script();
        script_mut_ref.as_mut_bytes()[0] = 4;
        assert_eq!(script.as_mut_bytes(), vec![4, 2, 3]);
    }

    #[test]
    fn script_buf_into_bytes() {
        let bytes = vec![1, 2, 3];
        let script = ScriptPubkeyBuf::from_bytes(bytes.clone());
        let result = script.into_bytes();
        assert_eq!(result, bytes);
    }

    #[test]
    fn script_buf_into_boxed_script() {
        let bytes = vec![1, 2, 3];
        let script = ScriptPubkeyBuf::from_bytes(bytes.clone());
        let boxed_script = script.into_boxed_script();
        assert_eq!(boxed_script.as_bytes(), bytes);
    }

    #[test]
    fn script_buf_capacity() {
        let script = ScriptPubkeyBuf::with_capacity(10);
        assert!(script.capacity() >= 10);
    }

    #[test]
    fn script_buf_reserve() {
        let mut script = ScriptPubkeyBuf::new();
        script.reserve(10);
        assert!(script.capacity() >= 10);
    }

    #[test]
    fn script_buf_reserve_exact() {
        let mut script = ScriptPubkeyBuf::new();
        script.reserve_exact(10);
        assert!(script.capacity() >= 10);
    }
}
