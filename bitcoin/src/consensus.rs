// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    encode::{deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt, VarInt},
    params::Params,
};
pub use primitives::consensus::*;

#[cfg(feature = "bitcoinconsensus")]
#[doc(inline)]
pub use self::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};

pub mod encode {
    //! Bitcoin consensus-encodable types.
    //!
    //! This is basically a replacement of the `Encodable` trait which does
    //! normalization of endianness etc., to ensure that the encoding matches
    //! the network consensus encoding.
    //!
    //! Essentially, anything that must go on the _disk_ or _network_ must be
    //! encoded using the `Encodable` trait, since this data must be the same for
    //! all systems. Any data going to the _user_ e.g., over JSONRPC, should use the
    //! ordinary `Encodable` trait. (This should also be the same across systems, of
    //! course, but has some critical differences from the network format e.g.,
    //! scripts come with an opcode decode, hashes are big-endian, numbers are
    //! typically big-endian decimals, etc.)

    pub use primitives::consensus::encode::*;

    #[cfg(test)]
    mod tests {
        use core::mem::discriminant;
        use core::{fmt, mem};

        use primitives::{BlockHash, TxMerkleNode};

        use super::*;
        use crate::bip158::FilterHash;
        #[cfg(feature = "std")]
        use crate::p2p::{message_blockdata::Inventory, Address};
        use crate::prelude::*;
        use crate::transaction::{Transaction, TxIn, TxOut};

        #[test]
        fn deserialize_vec_test() {
            assert_eq!(deserialize(&[3u8, 2, 3, 4]).ok(), Some(vec![2u8, 3, 4]));
            assert!((deserialize(&[4u8, 2, 3, 4, 5, 6]) as Result<Vec<u8>, _>).is_err());
            // found by cargo fuzz
            assert!(deserialize::<Vec<u64>>(&[
                0xff, 0xff, 0xff, 0xff, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
                0x6b, 0x6b, 0xa, 0xa, 0x3a
            ])
            .is_err());

            let rand_io_err = Error::Io(io::Error::new(io::ErrorKind::Other, ""));

            // Check serialization that `if len > MAX_VEC_SIZE {return err}` isn't inclusive,
            // by making sure it fails with IO Error and not an `OversizedVectorAllocation` Error.
            let err =
                deserialize::<CheckedData>(&serialize(&(super::MAX_VEC_SIZE as u32))).unwrap_err();
            assert_eq!(discriminant(&err), discriminant(&rand_io_err));

            test_len_is_max_vec::<u8>();
            test_len_is_max_vec::<BlockHash>();
            test_len_is_max_vec::<FilterHash>();
            test_len_is_max_vec::<TxMerkleNode>();
            test_len_is_max_vec::<Transaction>();
            test_len_is_max_vec::<TxOut>();
            test_len_is_max_vec::<TxIn>();
            test_len_is_max_vec::<Vec<u8>>();
            test_len_is_max_vec::<u64>();
            #[cfg(feature = "std")]
            test_len_is_max_vec::<(u32, Address)>();
            #[cfg(feature = "std")]
            test_len_is_max_vec::<Inventory>();
        }

        fn test_len_is_max_vec<T>()
        where
            Vec<T>: Decodable,
            T: fmt::Debug,
        {
            let rand_io_err = Error::Io(io::Error::new(io::ErrorKind::Other, ""));
            let varint = VarInt((super::MAX_VEC_SIZE / mem::size_of::<T>()) as u64);
            let err = deserialize::<Vec<T>>(&serialize(&varint)).unwrap_err();
            assert_eq!(discriminant(&err), discriminant(&rand_io_err));
        }
    }
}

pub mod params {
    // SPDX-License-Identifier: CC0-1.0

    //! Bitcoin consensus parameters.
    //!
    //! This module provides a predefined set of parameters for different Bitcoin
    //! chains (such as mainnet, testnet).
    //!
    //! # Custom Signets Example
    //!
    //! In various places in this crate we take `AsRef<Params>` as a parameter, in order to create a
    //! custom type that can be used is such places you might want to do the following:
    //!
    //! ```
    //! use bitcoin::consensus::Params;
    //! use bitcoin::{p2p, Script, ScriptBuf, Network, Target};
    //!
    //! const POW_TARGET_SPACING: u64 = 120; // Two minutes.
    //! const MAGIC: [u8; 4] = [1, 2, 3, 4];
    //!
    //! pub struct CustomParams {
    //!     params: Params,
    //!     magic: [u8; 4],
    //!     challenge_script: ScriptBuf,
    //! }
    //!
    //! impl CustomParams {
    //!     /// Creates a new custom params.
    //!     pub fn new() -> Self {
    //!         let mut params = Params::new(Network::Signet);
    //!         params.pow_target_spacing = POW_TARGET_SPACING;
    //!
    //!         // This would be something real (see BIP-325).
    //!         let challenge_script = ScriptBuf::new();
    //!
    //!         Self {
    //!             params,
    //!             magic: MAGIC,
    //!             challenge_script,
    //!         }
    //!     }
    //!
    //!     /// Returns the custom magic bytes.
    //!     pub fn magic(&self) -> p2p::Magic { p2p::Magic::from_bytes(self.magic) }
    //!
    //!     /// Returns the custom signet challenge script.
    //!     pub fn challenge_script(&self) -> &Script { &self.challenge_script }
    //! }
    //!
    //! impl AsRef<Params> for CustomParams {
    //!     fn as_ref(&self) -> &Params { &self.params }
    //! }
    //!
    //! impl Default for CustomParams {
    //!     fn default() -> Self { Self::new() }
    //! }
    //!
    //! # { // Just check the code above is usable.
    //! #    let target = Target::MAX_ATTAINABLE_SIGNET;
    //! #
    //! #    let signet = Params::SIGNET;
    //! #    let _ = target.difficulty(signet);
    //! #
    //! #    let custom = CustomParams::new();
    //! #    let _ = target.difficulty(custom);
    //! # }
    //! ```

    pub use primitives::params::*;
}

/// Re-export the consensus serde module.
#[cfg(feature = "serde")]
pub use primitives::consensus::serde;
/// Re-export the consensus validation module.
#[cfg(feature = "bitcoinconsensus")]
pub use primitives::consensus::validation;
