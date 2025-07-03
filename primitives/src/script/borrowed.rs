// SPDX-License-Identifier: CC0-1.0

use super::{
    ContextUnknownTag, RedeemScriptTag, ScriptPubkeyTag, ScriptSigTag, TapScriptTag,
    WitnessScriptTag,
};

/// A script with no specific known context.
pub type Script = tmp::Script<ContextUnknownTag>;

/// A scriptSig slice.
pub type ScriptSig = tmp::Script<ScriptSigTag>;

/// A scriptPubkey slice.
pub type ScriptPubkey = tmp::Script<ScriptPubkeyTag>;

/// A redeemScript slice.
pub type RedeemScript = tmp::Script<RedeemScriptTag>;

/// A witnessScript slice.
pub type WitnessScript = tmp::Script<WitnessScriptTag>;

/// A Tapscript slice.
pub type TapScript = tmp::Script<TapScriptTag>;

// TODO: This module can go away once we remove the `Script` alias. Added to make dev/review easier.
pub(in crate::script) mod tmp {
    use core::marker::PhantomData;
    use core::ops::{
        Bound, Index, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
    };

    #[cfg(feature = "arbitrary")]
    use arbitrary::{Arbitrary, Unstructured};

    use crate::prelude::{Box, ToOwned, Vec};
    use crate::script::{owned, Context};

    internals::transparent_newtype! {
        /// Bitcoin script slice.
        ///
        /// *[See also the `bitcoin::script` module](super).*
        ///
        /// `Script` is a script slice, the most primitive script type. It's usually seen in its borrowed
        /// form `&Script`. It is always encoded as a series of bytes representing the opcodes and data
        /// pushes.
        ///
        /// # Validity
        ///
        /// `Script` does not have any validity invariants - it's essentially just a marked slice of
        /// bytes. This is similar to [`Path`](std::path::Path) vs [`OsStr`](std::ffi::OsStr) where they
        /// are trivially cast-able to each-other and `Path` doesn't guarantee being a usable FS path but
        /// having a newtype still has value because of added methods, readability and basic type checking.
        ///
        /// Although at least data pushes could be checked not to overflow the script, bad scripts are
        /// allowed to be in a transaction (outputs just become unspendable) and there even are such
        /// transactions in the chain. Thus we must allow such scripts to be placed in the transaction.
        ///
        /// # Slicing safety
        ///
        /// Slicing is similar to how `str` works: some ranges may be incorrect and indexing by
        /// `usize` is not supported. However, as opposed to `std`, we have no way of checking
        /// correctness without causing linear complexity so there are **no panics on invalid
        /// ranges!** If you supply an invalid range, you'll get a garbled script.
        ///
        /// The range is considered valid if it's at a boundary of instruction. Care must be taken
        /// especially with push operations because you could get a reference to arbitrary
        /// attacker-supplied bytes that look like a valid script.
        ///
        /// It is recommended to use `.instructions()` method to get an iterator over script
        /// instructions and work with that instead.
        ///
        /// # Memory safety
        ///
        /// The type is `#[repr(transparent)]` for internal purposes only!
        /// No consumer crate may rely on the representation of the struct!
        ///
        /// # Hexadecimal strings
        ///
        /// Scripts are consensus encoded with a length prefix and as a result of this in some places in
        /// the eccosystem one will encounter hex strings that include the prefix while in other places
        /// the prefix is excluded. To support parsing and formatting scripts as hex we provide a bunch
        /// of different APIs and trait implementations. Please see [`examples/script.rs`] for a
        /// thorough example of all the APIs.
        ///
        /// # Bitcoin Core References
        ///
        /// * [CScript definition](https://github.com/bitcoin/bitcoin/blob/d492dc1cdaabdc52b0766bf4cba4bd73178325d0/src/script/script.h#L410)
        ///
        #[derive(PartialOrd, Ord, PartialEq, Eq, Hash)]
        pub struct Script<C>(PhantomData<C>, [u8]) where C: Context;

        impl<C> Script<C> {
            /// Treat byte slice as `Script`
            pub const fn from_bytes(bytes: &_) -> &Self;

            /// Treat mutable byte slice as `Script`
            pub fn from_bytes_mut(bytes: &mut _) -> &mut Self;

            pub(crate) fn from_boxed_bytes(bytes: Box<_>) -> Box<Self>;
            pub(crate) fn from_rc_bytes(bytes: Rc<_>) -> Rc<Self>;
            pub(crate) fn from_arc_bytes(bytes: Arc<_>) -> Arc<Self>;
        }
    }

    impl<C: Context + 'static> Default for &Script<C> {
        #[inline]
        fn default() -> Self { Script::<C>::new() }
    }

    impl<C: Context> ToOwned for Script<C> {
        type Owned = owned::tmp::ScriptBuf<C>;

        #[inline]
        fn to_owned(&self) -> Self::Owned { owned::tmp::ScriptBuf::from_bytes(self.to_vec()) }
    }

    impl<C: Context> Script<C> {
        /// Constructs a new empty script.
        #[inline]
        pub const fn new() -> &'static Self { Self::from_bytes(&[]) }

        /// Returns the script data as a byte slice.
        ///
        /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
        #[inline]
        pub const fn as_bytes(&self) -> &[u8] { &self.1 }

        /// Returns the script data as a mutable byte slice.
        ///
        /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
        #[inline]
        pub fn as_mut_bytes(&mut self) -> &mut [u8] { &mut self.1 }

        /// Returns a copy of the script data.
        ///
        /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
        #[inline]
        pub fn to_vec(&self) -> Vec<u8> { self.as_bytes().to_owned() }

        /// Returns a copy of the script data.
        #[inline]
        #[deprecated(since = "TBD", note = "use to_vec instead")]
        pub fn to_bytes(&self) -> Vec<u8> { self.to_vec() }

        /// Returns the length in bytes of the script.
        #[inline]
        pub const fn len(&self) -> usize { self.as_bytes().len() }

        /// Returns whether the script is the empty script.
        #[inline]
        pub const fn is_empty(&self) -> bool { self.as_bytes().is_empty() }

        /// Converts a [`Box<Script>`](Box) into a [`ScriptBuf`] without copying or allocating.
        #[must_use]
        #[inline]
        pub fn into_script_buf(self: Box<Self>) -> owned::tmp::ScriptBuf<C> {
            let rw = Box::into_raw(self) as *mut [u8];
            // SAFETY: copied from `std`
            // The pointer was just created from a box without deallocating
            // Casting a transparent struct wrapping a slice to the slice pointer is sound (same
            // layout).
            let inner = unsafe { Box::from_raw(rw) };
            owned::tmp::ScriptBuf::from_bytes(Vec::from(inner))
        }

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

    #[cfg(feature = "arbitrary")]
    impl<'a, C: Context> Arbitrary<'a> for &'a Script<C> {
        #[inline]
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let v = <&'a [u8]>::arbitrary(u)?;
            Ok(Script::from_bytes(v))
        }
    }

    macro_rules! delegate_index {
        ($($type:ty),* $(,)?) => {
            $(
                /// Script subslicing operation - read [slicing safety](#slicing-safety)!
                impl<C: Context> Index<$type> for Script<C> {
                    type Output = Self;

                    #[inline]
                    fn index(&self, index: $type) -> &Self::Output {
                        Self::from_bytes(&self.as_bytes()[index])
                    }
                }
            )*
        }
    }

    delegate_index!(
        Range<usize>,
        RangeFrom<usize>,
        RangeTo<usize>,
        RangeFull,
        RangeInclusive<usize>,
        RangeToInclusive<usize>,
        (Bound<usize>, Bound<usize>)
    );
}

impl ScriptSig {
    /// Returns this scriptSig as if there is no known context.
    // FIXME: Once script tagging is done I don't think we want this?
    #[deprecated(since = "TBD", note = "once script tagging is done this should not be needed")]
    pub fn as_context_unknown(&self) -> &Script { Script::from_bytes(self.as_bytes()) }
}

impl ScriptPubkey {
    /// Adds context to this scriptPubkey returning a [`RedeemScript`].
    pub fn as_redeem_script(&self) -> &RedeemScript { RedeemScript::from_bytes(self.as_bytes()) }

    /// Adds context to this scriptPubkey returning a [`WitnessScript`].
    pub fn as_witness_script(&self) -> &WitnessScript { WitnessScript::from_bytes(self.as_bytes()) }

    /// Adds context to this scriptPubkey returning a [`TapScript`].
    pub fn as_tap_script(&self) -> &TapScript { TapScript::from_bytes(self.as_bytes()) }

    /// Removes context from this scriptPubkey.
    // Once script tagging is done this should not be needed.
    #[deprecated(since = "TBD", note = "once script tagging is done this should not be needed")]
    pub fn as_context_unknown(&self) -> &Script { Script::from_bytes(self.as_bytes()) }
}

impl RedeemScript {
    /// Removes context from this redeemScript returning a [`ScriptPubkey`].
    pub fn as_script_pubkey(&self) -> &ScriptPubkey { ScriptPubkey::from_bytes(self.as_bytes()) }
}

impl WitnessScript {
    /// Removes context from this witnessScript returning a [`ScriptPubkey`].
    pub fn as_script_pubkey(&self) -> &ScriptPubkey { ScriptPubkey::from_bytes(self.as_bytes()) }
}

impl TapScript {
    /// Removes context from this `TapScript` returning a [`ScriptPubkey`].
    pub fn as_script_pubkey(&self) -> &ScriptPubkey { ScriptPubkey::from_bytes(self.as_bytes()) }
}

impl tmp::Script<ContextUnknownTag> {
    /// Adds context to this script returning a [`ScriptSig`].
    pub fn as_script_sig(&self) -> &ScriptSig { ScriptSig::from_bytes(self.as_bytes()) }

    /// Adds context to this script returning a [`ScriptPubkey`].
    pub fn as_script_pubkey(&self) -> &ScriptPubkey { ScriptPubkey::from_bytes(self.as_bytes()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_from_bytes() {
        let script = Script::from_bytes(&[1, 2, 3]);
        assert_eq!(script.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn script_from_bytes_mut() {
        let bytes = &mut [1, 2, 3];
        let script = Script::from_bytes_mut(bytes);
        script.as_mut_bytes()[0] = 4;
        assert_eq!(script.as_mut_bytes(), [4, 2, 3]);
    }

    #[test]
    fn script_to_vec() {
        let script = Script::from_bytes(&[1, 2, 3]);
        assert_eq!(script.to_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn script_len() {
        let script = Script::from_bytes(&[1, 2, 3]);
        assert_eq!(script.len(), 3);
    }

    #[test]
    fn script_is_empty() {
        let script: &Script = Default::default();
        assert!(script.is_empty());

        let script = Script::from_bytes(&[1, 2, 3]);
        assert!(!script.is_empty());
    }

    #[test]
    fn script_to_owned() {
        let script = Script::from_bytes(&[1, 2, 3]);
        let script_buf = script.to_owned();
        assert_eq!(script_buf.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn test_index() {
        let script = Script::from_bytes(&[1, 2, 3, 4, 5]);

        assert_eq!(script[1..3].as_bytes(), &[2, 3]);
        assert_eq!(script[2..].as_bytes(), &[3, 4, 5]);
        assert_eq!(script[..3].as_bytes(), &[1, 2, 3]);
        assert_eq!(script[..].as_bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(script[1..=3].as_bytes(), &[2, 3, 4]);
        assert_eq!(script[..=2].as_bytes(), &[1, 2, 3]);
    }
}
