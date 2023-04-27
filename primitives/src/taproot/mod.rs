// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Taproot.
//!
//! This module provides support for taproot tagged hashes.

use core::fmt;

#[cfg(feature = "crypto")] // FIXME: Can we reduce the feature gate scope?
pub mod merkle_branch;
#[cfg(feature = "crypto")]
pub mod serialized_signature;

use hashes::{sha256t_hash_newtype, Hash, HashEngine};
#[cfg(feature = "crypto")]
use secp256k1::Scalar;

use crate::consensus::Encodable;
#[cfg(feature = "crypto")]
use crate::key::{TapTweak, TweakedPublicKey, UntweakedPublicKey, XOnlyPublicKey};
use crate::Script;

// Re-export these so downstream only has to use one `taproot` module.
#[rustfmt::skip]
#[doc(inline)]
#[cfg(feature = "crypto")]
pub use crate::crypto::taproot::{SigFromSliceError, Signature};
#[doc(inline)]
#[cfg(feature = "crypto")]
pub use merkle_branch::TaprootMerkleBranch;

// Taproot test vectors from BIP-341 state the hashes without any reversing
sha256t_hash_newtype! {
    pub struct TapLeafTag = hash_str("TapLeaf");

    /// Taproot-tagged hash with tag \"TapLeaf\".
    ///
    /// This is used for computing tapscript script spend hash.
    pub struct TapLeafHash(_);

    pub struct TapBranchTag = hash_str("TapBranch");

    /// Tagged hash used in taproot trees.
    ///
    /// See BIP-340 for tagging rules.
    pub struct TapNodeHash(_);

    pub struct TapTweakTag = hash_str("TapTweak");

    /// Taproot-tagged hash with tag \"TapTweak\".
    ///
    /// This hash type is used while computing the tweaked public key.
    pub struct TapTweakHash(_);
}

impl TapTweakHash {
    /// Creates a new BIP341 [`TapTweakHash`] from key and tweak. Produces `H_taptweak(P||R)` where
    /// `P` is the internal key and `R` is the merkle root.
    #[cfg(feature = "crypto")]
    pub fn from_key_and_tweak(
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> TapTweakHash {
        let mut eng = TapTweakHash::engine();
        // always hash the key
        eng.input(&internal_key.serialize());
        if let Some(h) = merkle_root {
            eng.input(h.as_ref());
        } else {
            // nothing to hash
        }
        TapTweakHash::from_engine(eng)
    }

    /// Converts a `TapTweakHash` into a `Scalar` ready for use with key tweaking API.
    #[cfg(feature = "crypto")]
    pub fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl TapLeafHash {
    /// Computes the leaf hash from components.
    pub fn from_script(script: &Script, ver: LeafVersion) -> TapLeafHash {
        let mut eng = TapLeafHash::engine();
        ver.to_consensus().consensus_encode(&mut eng).expect("engines don't error");
        script.consensus_encode(&mut eng).expect("engines don't error");
        TapLeafHash::from_engine(eng)
    }
}

impl TapNodeHash {
    /// Computes branch hash given two hashes of the nodes underneath it.
    pub fn from_node_hashes(a: TapNodeHash, b: TapNodeHash) -> TapNodeHash {
        Self::combine_node_hashes(a, b).0
    }

    /// Computes branch hash given two hashes of the nodes underneath it and returns
    /// whether the left node was the one hashed first.
    fn combine_node_hashes(a: TapNodeHash, b: TapNodeHash) -> (TapNodeHash, bool) {
        let mut eng = TapNodeHash::engine();
        if a < b {
            eng.input(a.as_ref());
            eng.input(b.as_ref());
        } else {
            eng.input(b.as_ref());
            eng.input(a.as_ref());
        };
        (TapNodeHash::from_engine(eng), a < b)
    }

    /// Assumes the given 32 byte array as hidden [`TapNodeHash`].
    ///
    /// Similar to [`TapLeafHash::from_byte_array`], but explicitly conveys that the
    /// hash is constructed from a hidden node. This also has better ergonomics
    /// because it does not require the caller to import the Hash trait.
    pub fn assume_hidden(hash: [u8; 32]) -> TapNodeHash { TapNodeHash::from_byte_array(hash) }

    /// Computes the [`TapNodeHash`] from a script and a leaf version.
    pub fn from_script(script: &Script, ver: LeafVersion) -> TapNodeHash {
        TapNodeHash::from(TapLeafHash::from_script(script, ver))
    }
}

impl From<TapLeafHash> for TapNodeHash {
    fn from(leaf: TapLeafHash) -> TapNodeHash { TapNodeHash::from_byte_array(leaf.to_byte_array()) }
}

/// Maximum depth of a taproot tree script spend path.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L229
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// Size of a taproot control node.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L228
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// Tapleaf mask for getting the leaf version from first byte of control block.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L225
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// Tapscript leaf version.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L226
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Taproot annex prefix.
pub const TAPROOT_ANNEX_PREFIX: u8 = 0x50;
/// Tapscript control base size.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L227
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// Tapscript control max size.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L230
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

/// The leaf version for tapleafs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafVersion {
    /// BIP-342 tapscript.
    TapScript,

    /// Future leaf version.
    Future(FutureLeafVersion),
}

impl LeafVersion {
    /// Creates a [`LeafVersion`] from consensus byte representation.
    ///
    /// # Errors
    ///
    /// - If the last bit of the `version` is odd.
    /// - If the `version` is 0x50 ([`TAPROOT_ANNEX_PREFIX`]).
    pub fn from_consensus(version: u8) -> Result<Self, LeafVersionError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => Ok(LeafVersion::TapScript),
            TAPROOT_ANNEX_PREFIX => Err(LeafVersionError(TAPROOT_ANNEX_PREFIX)),
            future => FutureLeafVersion::from_consensus(future).map(LeafVersion::Future),
        }
    }

    /// Returns the consensus representation of this [`LeafVersion`].
    pub fn to_consensus(self) -> u8 {
        match self {
            LeafVersion::TapScript => TAPROOT_LEAF_TAPSCRIPT,
            LeafVersion::Future(version) => version.to_consensus(),
        }
    }
}

impl fmt::Display for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self, f.alternate()) {
            (LeafVersion::TapScript, true) => f.write_str("tapscript"),
            (LeafVersion::TapScript, false) => fmt::Display::fmt(&TAPROOT_LEAF_TAPSCRIPT, f),
            (LeafVersion::Future(version), true) => write!(f, "future_script_{:#02x}", version.0),
            (LeafVersion::Future(version), false) => fmt::Display::fmt(version, f),
        }
    }
}

impl fmt::LowerHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_consensus(), f)
    }
}

impl fmt::UpperHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.to_consensus(), f)
    }
}

/// Serializes [`LeafVersion`] as a `u8` using consensus encoding.
#[cfg(feature = "serde")]
impl serde::Serialize for LeafVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.to_consensus())
    }
}

/// Deserializes [`LeafVersion`] as a `u8` using consensus encoding.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LeafVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct U8Visitor;
        impl<'de> serde::de::Visitor<'de> for U8Visitor {
            type Value = LeafVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid consensus-encoded taproot leaf version")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = u8::try_from(value).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Unsigned(value),
                        &"consensus-encoded leaf version as u8",
                    )
                })?;
                LeafVersion::from_consensus(value).map_err(|_| {
                    E::invalid_value(
                        ::serde::de::Unexpected::Unsigned(value as u64),
                        &"consensus-encoded leaf version as u8",
                    )
                })
            }
        }

        deserializer.deserialize_u8(U8Visitor)
    }
}

/// Inner type representing future (non-tapscript) leaf versions. See [`LeafVersion::Future`].
///
/// NB: NO PUBLIC CONSTRUCTOR!
/// The only way to construct this is by converting `u8` to [`LeafVersion`] and then extracting it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FutureLeafVersion(u8);

impl FutureLeafVersion {
    pub(self) fn from_consensus(version: u8) -> Result<FutureLeafVersion, LeafVersionError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => unreachable!(
                "FutureLeafVersion::from_consensus should be never called for 0xC0 value"
            ),
            TAPROOT_ANNEX_PREFIX => Err(LeafVersionError(TAPROOT_ANNEX_PREFIX)),
            odd if odd & 0xFE != odd => Err(LeafVersionError(odd)),
            even => Ok(FutureLeafVersion(even)),
        }
    }

    /// Returns the consensus representation of this [`FutureLeafVersion`].
    #[inline]
    pub fn to_consensus(self) -> u8 { self.0 }
}

impl fmt::Display for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::LowerHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

/// The last bit of tapleaf version must be zero.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LeafVersionError(pub u8); // FIXME: I don't have error policy within my brain right now.

internals::impl_from_infallible!(LeafVersionError);

impl fmt::Display for LeafVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Leaf version({}) must have the least significant bit 0", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LeafVersionError {}

/// The `crypto` module is just so we can feature gate more easily.
#[cfg(feature = "crypto")]
pub use crypto::*;

#[cfg(feature = "crypto")]
mod crypto {
    use core::cmp::Reverse;
    use core::fmt;
    use core::iter::FusedIterator;

    use internals::write_err;
    use io::Write;
    use secp256k1::Secp256k1;

    use super::*;
    use crate::prelude::*;
    use crate::ScriptBuf;

    // type alias for versioned tap script corresponding merkle proof
    type ScriptMerkleProofMap = BTreeMap<(ScriptBuf, LeafVersion), BTreeSet<TaprootMerkleBranch>>;

    /// Represents taproot spending information.
    ///
    /// Taproot output corresponds to a combination of a single public key condition (known as the
    /// internal key), and zero or more general conditions encoded in scripts organized in the form of a
    /// binary tree.
    ///
    /// Taproot can be spent by either:
    /// - Spending using the key path i.e., with secret key corresponding to the tweaked `output_key`.
    /// - By satisfying any of the scripts in the script spend path. Each script can be satisfied by
    ///   providing a witness stack consisting of the script's inputs, plus the script itself and the
    ///   control block.
    ///
    /// If one or more of the spending conditions consist of just a single key (after aggregation), the
    /// most likely key should be made the internal key.
    /// See [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) for more details on
    /// choosing internal keys for a taproot application.
    ///
    /// Note: This library currently does not support
    /// [annex](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-5).
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TaprootSpendInfo {
        /// The BIP341 internal key.
        internal_key: UntweakedPublicKey,
        /// The merkle root of the script tree (None if there are no scripts).
        merkle_root: Option<TapNodeHash>,
        /// The sign final output pubkey as per BIP 341.
        output_key_parity: secp256k1::Parity,
        /// The tweaked output key.
        output_key: TweakedPublicKey,
        /// Map from (script, leaf_version) to (sets of) [`TaprootMerkleBranch`]. More than one control
        /// block for a given script is only possible if it appears in multiple branches of the tree. In
        /// all cases, keeping one should be enough for spending funds, but we keep all of the paths so
        /// that a full tree can be constructed again from spending data if required.
        script_map: ScriptMerkleProofMap,
    }

    impl TaprootSpendInfo {
        /// Creates a new [`TaprootSpendInfo`] from a list of scripts (with default script version) and
        /// weights of satisfaction for that script.
        ///
        /// See [`TaprootBuilder::with_huffman_tree`] for more detailed documentation.
        pub fn with_huffman_tree<C, I>(
            secp: &Secp256k1<C>,
            internal_key: UntweakedPublicKey,
            script_weights: I,
        ) -> Result<Self, TaprootBuilderError>
        where
            I: IntoIterator<Item = (u32, ScriptBuf)>,
            C: secp256k1::Verification,
        {
            let builder = TaprootBuilder::with_huffman_tree(script_weights)?;
            Ok(builder.finalize(secp, internal_key).expect("Huffman Tree is always complete"))
        }

        /// Creates a new key spend with `internal_key` and `merkle_root`. Provide [`None`] for
        /// the `merkle_root` if there is no script path.
        ///
        /// *Note*: As per BIP341
        ///
        /// When the merkle root is [`None`], the output key commits to an unspendable script path
        /// instead of having no script path. This is achieved by computing the output key point as
        /// `Q = P + int(hashTapTweak(bytes(P)))G`. See also [`TaprootSpendInfo::tap_tweak`].
        ///
        /// Refer to BIP 341 footnote ('Why should the output key always have a taproot commitment, even
        /// if there is no script path?') for more details.
        pub fn new_key_spend<C: secp256k1::Verification>(
            secp: &Secp256k1<C>,
            internal_key: UntweakedPublicKey,
            merkle_root: Option<TapNodeHash>,
        ) -> Self {
            let (output_key, parity) = internal_key.tap_tweak(secp, merkle_root);
            Self {
                internal_key,
                merkle_root,
                output_key_parity: parity,
                output_key,
                script_map: BTreeMap::new(),
            }
        }

        /// Returns the `TapTweakHash` for this [`TaprootSpendInfo`] i.e., the tweak using `internal_key`
        /// and `merkle_root`.
        pub fn tap_tweak(&self) -> TapTweakHash {
            TapTweakHash::from_key_and_tweak(self.internal_key, self.merkle_root)
        }

        /// Returns the internal key for this [`TaprootSpendInfo`].
        pub fn internal_key(&self) -> UntweakedPublicKey { self.internal_key }

        /// Returns the merkle root for this [`TaprootSpendInfo`].
        pub fn merkle_root(&self) -> Option<TapNodeHash> { self.merkle_root }

        /// Returns the output key (the key used in script pubkey) for this [`TaprootSpendInfo`].
        pub fn output_key(&self) -> TweakedPublicKey { self.output_key }

        /// Returns the parity of the output key. See also [`TaprootSpendInfo::output_key`].
        pub fn output_key_parity(&self) -> secp256k1::Parity { self.output_key_parity }

        /// Returns a reference to the internal script map.
        pub fn script_map(&self) -> &ScriptMerkleProofMap { &self.script_map }

        /// Computes the [`TaprootSpendInfo`] from `internal_key` and `node`.
        ///
        /// This is useful when you want to manually build a taproot tree without using
        /// [`TaprootBuilder`].
        pub fn from_node_info<C: secp256k1::Verification>(
            secp: &Secp256k1<C>,
            internal_key: UntweakedPublicKey,
            node: NodeInfo,
        ) -> TaprootSpendInfo {
            // Create as if it is a key spend path with the given merkle root
            let root_hash = Some(node.hash);
            let mut info = TaprootSpendInfo::new_key_spend(secp, internal_key, root_hash);

            for leaves in node.leaves {
                match leaves.leaf {
                    TapLeaf::Hidden(_) => {
                        // We don't store any information about hidden nodes in TaprootSpendInfo.
                    }
                    TapLeaf::Script(script, ver) => {
                        let key = (script, ver);
                        let value = leaves.merkle_branch;
                        match info.script_map.get_mut(&key) {
                            None => {
                                let mut set = BTreeSet::new();
                                set.insert(value);
                                info.script_map.insert(key, set);
                            }
                            Some(set) => {
                                set.insert(value);
                            }
                        }
                    }
                }
            }
            info
        }

        /// Constructs a [`ControlBlock`] for particular script with the given version.
        ///
        /// # Returns
        ///
        /// - If there are multiple control blocks possible, returns the shortest one.
        /// - If the script is not contained in the [`TaprootSpendInfo`], returns `None`.
        pub fn control_block(&self, script_ver: &(ScriptBuf, LeafVersion)) -> Option<ControlBlock> {
            let merkle_branch_set = self.script_map.get(script_ver)?;
            // Choose the smallest one amongst the multiple script maps
            let smallest = merkle_branch_set
                .iter()
                .min_by(|x, y| x.len().cmp(&y.len()))
                .expect("Invariant: ScriptBuf map key must contain non-empty set value");
            Some(ControlBlock {
                internal_key: self.internal_key,
                output_key_parity: self.output_key_parity,
                leaf_version: script_ver.1,
                merkle_branch: smallest.clone(),
            })
        }
    }

    impl From<TaprootSpendInfo> for TapTweakHash {
        fn from(spend_info: TaprootSpendInfo) -> TapTweakHash { spend_info.tap_tweak() }
    }

    impl From<&TaprootSpendInfo> for TapTweakHash {
        fn from(spend_info: &TaprootSpendInfo) -> TapTweakHash { spend_info.tap_tweak() }
    }

    /// Builder for building taproot iteratively. Users can specify tap leaf or omitted/hidden branches
    /// in a depth-first search (DFS) walk order to construct this tree.
    ///
    /// See Wikipedia for more details on [DFS](https://en.wikipedia.org/wiki/Depth-first_search).
    // Similar to Taproot Builder in Bitcoin Core.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TaprootBuilder {
        // The following doc-comment is from Bitcoin Core, but modified for Rust. It describes the
        // current state of the builder for a given tree.
        //
        // For each level in the tree, one NodeInfo object may be present. Branch at index 0 is
        // information about the root; further values are for deeper subtrees being explored.
        //
        // During the construction of Taptree, for every right branch taken to reach the position we're
        // currently working on, there will be a `(Some(_))` entry in branch corresponding to the left
        // branch at that level.
        //
        // For example, imagine this tree:     - N0 -
        //                                    /      \
        //                                   N1      N2
        //                                  /  \    /  \
        //                                 A    B  C   N3
        //                                            /  \
        //                                           D    E
        //
        // Initially, branch is empty. After processing leaf A, it would become {None, None, A}. When
        // processing leaf B, an entry at level 2 already exists, and it would thus be combined with it
        // to produce a level 1 entry, resulting in {None, N1}. Adding C and D takes us to {None, N1, C}
        // and {None, N1, C, D} respectively. When E is processed, it is combined with D, and then C,
        // and then N1, to produce the root, resulting in {N0}.
        //
        // This structure allows processing with just O(log n) overhead if the leaves are computed on
        // the fly.
        //
        // As an invariant, there can never be None entries at the end. There can also not be more than
        // 128 entries (as that would mean more than 128 levels in the tree). The depth of newly added
        // entries will always be at least equal to the current size of branch (otherwise it does not
        // correspond to a depth-first traversal of a tree). A branch is only empty if no entries have
        // ever be processed. A branch having length 1 corresponds to being done.
        branch: Vec<Option<NodeInfo>>,
    }

    impl TaprootBuilder {
        /// Creates a new instance of [`TaprootBuilder`].
        pub fn new() -> Self { TaprootBuilder { branch: vec![] } }

        /// Creates a new instance of [`TaprootBuilder`] with a capacity hint for `size` elements.
        ///
        /// The size here should be maximum depth of the tree.
        pub fn with_capacity(size: usize) -> Self {
            TaprootBuilder { branch: Vec::with_capacity(size) }
        }

        /// Creates a new [`TaprootSpendInfo`] from a list of scripts (with default script version) and
        /// weights of satisfaction for that script.
        ///
        /// The weights represent the probability of each branch being taken. If probabilities/weights
        /// for each condition are known, constructing the tree as a Huffman Tree is the optimal way to
        /// minimize average case satisfaction cost. This function takes as input an iterator of
        /// `tuple(u32, ScriptBuf)` where `u32` represents the satisfaction weights of the branch. For
        /// example, [(3, S1), (2, S2), (5, S3)] would construct a [`TapTree`] that has optimal
        /// satisfaction weight when probability for S1 is 30%, S2 is 20% and S3 is 50%.
        ///
        /// # Errors:
        ///
        /// - When the optimal Huffman Tree has a depth more than 128.
        /// - If the provided list of script weights is empty.
        ///
        /// # Edge Cases:
        ///
        /// If the script weight calculations overflow, a sub-optimal tree may be generated. This should
        /// not happen unless you are dealing with billions of branches with weights close to 2^32.
        ///
        /// [`TapTree`]: crate::taproot::TapTree
        pub fn with_huffman_tree<I>(script_weights: I) -> Result<Self, TaprootBuilderError>
        where
            I: IntoIterator<Item = (u32, ScriptBuf)>,
        {
            let mut node_weights = BinaryHeap::<(Reverse<u32>, NodeInfo)>::new();
            for (p, leaf) in script_weights {
                node_weights
                    .push((Reverse(p), NodeInfo::new_leaf_with_ver(leaf, LeafVersion::TapScript)));
            }
            if node_weights.is_empty() {
                return Err(TaprootBuilderError::EmptyTree);
            }
            while node_weights.len() > 1 {
                // Combine the last two elements and insert a new node
                let (p1, s1) = node_weights.pop().expect("len must be at least two");
                let (p2, s2) = node_weights.pop().expect("len must be at least two");
                // Insert the sum of first two in the tree as a new node
                // N.B.: p1 + p2 can not practically saturate as you would need to have 2**32 max u32s
                // from the input to overflow. However, saturating is a reasonable behavior here as
                // huffman tree construction would treat all such elements as "very likely".
                let p = Reverse(p1.0.saturating_add(p2.0));
                node_weights.push((p, NodeInfo::combine(s1, s2)?));
            }
            // Every iteration of the loop reduces the node_weights.len() by exactly 1
            // Therefore, the loop will eventually terminate with exactly 1 element
            debug_assert_eq!(node_weights.len(), 1);
            let node = node_weights.pop().expect("huffman tree algorithm is broken").1;
            Ok(TaprootBuilder { branch: vec![Some(node)] })
        }

        /// Adds a leaf script at `depth` to the builder with script version `ver`.
        ///
        /// The depth of the root node is 0.
        ///
        /// # Errors
        ///
        /// Errors if the leaves are not provided in DFS walk order.
        pub fn add_leaf_with_ver(
            self,
            depth: u8,
            script: ScriptBuf,
            ver: LeafVersion,
        ) -> Result<Self, TaprootBuilderError> {
            let leaf = NodeInfo::new_leaf_with_ver(script, ver);
            self.insert(leaf, depth)
        }

        /// Adds a leaf script at `depth` to the builder with default script version.
        ///
        /// The depth of the root node is 0.
        ///
        /// See [`TaprootBuilder::add_leaf_with_ver`] for adding a leaf with specific version.
        ///
        /// # Errors
        ///
        /// Errors if the leaves are not provided in DFS walk order.
        pub fn add_leaf(self, depth: u8, script: ScriptBuf) -> Result<Self, TaprootBuilderError> {
            self.add_leaf_with_ver(depth, script, LeafVersion::TapScript)
        }

        /// Adds a hidden/omitted node at `depth` to the builder.
        ///
        /// The depth of the root node is 0.
        ///
        /// # Errors
        ///
        /// Errors if the leaves are not provided in DFS walk order.
        pub fn add_hidden_node(
            self,
            depth: u8,
            hash: TapNodeHash,
        ) -> Result<Self, TaprootBuilderError> {
            let node = NodeInfo::new_hidden_node(hash);
            self.insert(node, depth)
        }

        /// Checks if the builder has finalized building a tree.
        pub fn is_finalizable(&self) -> bool { self.branch.len() == 1 && self.branch[0].is_some() }

        /// Converts the builder into a [`NodeInfo`] if the builder is a full tree with possibly
        /// hidden nodes
        ///
        /// # Errors:
        ///
        /// [`IncompleteBuilderError::NotFinalized`] if the builder is not finalized. The builder
        /// can be restored by calling [`IncompleteBuilderError::into_builder`]
        pub fn try_into_node_info(mut self) -> Result<NodeInfo, IncompleteBuilderError> {
            if self.branch().len() != 1 {
                return Err(IncompleteBuilderError::NotFinalized(self));
            }
            Ok(self
                .branch
                .pop()
                .expect("length checked above")
                .expect("invariant guarantees node info exists"))
        }

        /// Converts the builder into a [`TapTree`] if the builder is a full tree and
        /// does not contain any hidden nodes
        pub fn try_into_taptree(self) -> Result<TapTree, IncompleteBuilderError> {
            let node = self.try_into_node_info()?;
            if node.has_hidden_nodes {
                // Reconstruct the builder as it was if it has hidden nodes
                return Err(IncompleteBuilderError::HiddenParts(TaprootBuilder {
                    branch: vec![Some(node)],
                }));
            }
            Ok(TapTree(node))
        }

        /// Checks if the builder has hidden nodes.
        pub fn has_hidden_nodes(&self) -> bool {
            self.branch.iter().flatten().any(|node| node.has_hidden_nodes)
        }

        /// Creates a [`TaprootSpendInfo`] with the given internal key.
        ///
        /// Returns the unmodified builder as Err if the builder is not finalizable.
        /// See also [`TaprootBuilder::is_finalizable`]
        pub fn finalize<C: secp256k1::Verification>(
            mut self,
            secp: &Secp256k1<C>,
            internal_key: UntweakedPublicKey,
        ) -> Result<TaprootSpendInfo, TaprootBuilder> {
            match self.branch.len() {
                0 => Ok(TaprootSpendInfo::new_key_spend(secp, internal_key, None)),
                1 =>
                    if let Some(Some(node)) = self.branch.pop() {
                        Ok(TaprootSpendInfo::from_node_info(secp, internal_key, node))
                    } else {
                        unreachable!(
                            "Size checked above. Builder guarantees the last element is Some"
                        )
                    },
                _ => Err(self),
            }
        }

        pub(crate) fn branch(&self) -> &[Option<NodeInfo>] { &self.branch }

        /// Inserts a leaf at `depth`.
        fn insert(
            mut self,
            mut node: NodeInfo,
            mut depth: u8,
        ) -> Result<Self, TaprootBuilderError> {
            // early error on invalid depth. Though this will be checked later
            // while constructing TaprootMerkelBranch
            if depth as usize > TAPROOT_CONTROL_MAX_NODE_COUNT {
                return Err(TaprootBuilderError::InvalidMerkleTreeDepth(depth as usize));
            }
            // We cannot insert a leaf at a lower depth while a deeper branch is unfinished. Doing
            // so would mean the add_leaf/add_hidden invocations do not correspond to a DFS traversal of a
            // binary tree.
            if (depth as usize + 1) < self.branch.len() {
                return Err(TaprootBuilderError::NodeNotInDfsOrder);
            }

            while self.branch.len() == depth as usize + 1 {
                let child = match self.branch.pop() {
                    None => unreachable!("Len of branch checked to be >= 1"),
                    Some(Some(child)) => child,
                    // Needs an explicit push to add the None that we just popped.
                    // Cannot use .last() because of borrow checker issues.
                    Some(None) => {
                        self.branch.push(None);
                        break;
                    } // Cannot combine further
                };
                if depth == 0 {
                    // We are trying to combine two nodes at root level.
                    // Can't propagate further up than the root
                    return Err(TaprootBuilderError::OverCompleteTree);
                }
                node = NodeInfo::combine(node, child)?;
                // Propagate to combine nodes at a lower depth
                depth -= 1;
            }

            if self.branch.len() < depth as usize + 1 {
                // add enough nodes so that we can insert node at depth `depth`
                let num_extra_nodes = depth as usize + 1 - self.branch.len();
                self.branch.extend((0..num_extra_nodes).map(|_| None));
            }
            // Push the last node to the branch
            self.branch[depth as usize] = Some(node);
            Ok(self)
        }
    }

    impl Default for TaprootBuilder {
        fn default() -> Self { Self::new() }
    }

    /// Error happening when [`TapTree`] is constructed from a [`TaprootBuilder`]
    /// having hidden branches or not being finalized.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum IncompleteBuilderError {
        /// Indicates an attempt to construct a tap tree from a builder containing incomplete branches.
        NotFinalized(TaprootBuilder),
        /// Indicates an attempt to construct a tap tree from a builder containing hidden parts.
        HiddenParts(TaprootBuilder),
    }

    internals::impl_from_infallible!(IncompleteBuilderError);

    impl IncompleteBuilderError {
        /// Converts error into the original incomplete [`TaprootBuilder`] instance.
        pub fn into_builder(self) -> TaprootBuilder {
            use IncompleteBuilderError::*;

            match self {
                NotFinalized(builder) | HiddenParts(builder) => builder,
            }
        }
    }

    impl core::fmt::Display for IncompleteBuilderError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            use IncompleteBuilderError::*;

            f.write_str(match self {
                NotFinalized(_) =>
                    "an attempt to construct a tap tree from a builder containing incomplete branches.",
                HiddenParts(_) =>
                    "an attempt to construct a tap tree from a builder containing hidden parts.",
            })
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for IncompleteBuilderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use IncompleteBuilderError::*;

            match *self {
                NotFinalized(_) | HiddenParts(_) => None,
            }
        }
    }

    /// Error happening when [`TapTree`] is constructed from a [`NodeInfo`]
    /// having hidden branches.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum HiddenNodesError {
        /// Indicates an attempt to construct a tap tree from a builder containing hidden parts.
        HiddenParts(NodeInfo),
    }

    internals::impl_from_infallible!(HiddenNodesError);

    impl HiddenNodesError {
        /// Converts error into the original incomplete [`NodeInfo`] instance.
        pub fn into_node_info(self) -> NodeInfo {
            use HiddenNodesError::*;

            match self {
                HiddenParts(node_info) => node_info,
            }
        }
    }

    impl core::fmt::Display for HiddenNodesError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            use HiddenNodesError::*;

            f.write_str(match self {
                HiddenParts(_) =>
                    "an attempt to construct a tap tree from a node_info containing hidden parts.",
            })
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HiddenNodesError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use HiddenNodesError::*;

            match self {
                HiddenParts(_) => None,
            }
        }
    }

    /// Taproot Tree representing a complete binary tree without any hidden nodes.
    ///
    /// This is in contrast to [`NodeInfo`], which allows hidden nodes.
    /// The implementations for Eq, PartialEq and Hash compare the merkle root of the tree
    //
    // This is a bug in BIP370 that does not specify how to share trees with hidden nodes,
    // for which we need a separate type.
    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
    #[cfg_attr(feature = "serde", serde(into = "NodeInfo"))]
    #[cfg_attr(feature = "serde", serde(try_from = "NodeInfo"))]
    pub struct TapTree(NodeInfo);

    impl From<TapTree> for NodeInfo {
        #[inline]
        fn from(tree: TapTree) -> Self { tree.into_node_info() }
    }

    impl TapTree {
        /// Gets the reference to inner [`NodeInfo`] of this tree root.
        pub fn node_info(&self) -> &NodeInfo { &self.0 }

        /// Gets the inner [`NodeInfo`] of this tree root.
        pub fn into_node_info(self) -> NodeInfo { self.0 }

        /// Returns [`TapTreeIter<'_>`] iterator for a taproot script tree, operating in DFS order over
        /// tree [`ScriptLeaf`]s.
        pub fn script_leaves(&self) -> ScriptLeaves {
            ScriptLeaves { leaf_iter: self.0.leaf_nodes() }
        }

        /// Returns the root [`TapNodeHash`] of this tree.
        pub fn root_hash(&self) -> TapNodeHash { self.0.hash }
    }

    impl TryFrom<TaprootBuilder> for TapTree {
        type Error = IncompleteBuilderError;

        /// Constructs [`TapTree`] from a [`TaprootBuilder`] if it is complete binary tree.
        ///
        /// # Returns
        ///
        /// A [`TapTree`] iff the `builder` is complete, otherwise return [`IncompleteBuilderError`]
        /// error with the content of incomplete `builder` instance.
        fn try_from(builder: TaprootBuilder) -> Result<Self, Self::Error> {
            builder.try_into_taptree()
        }
    }

    impl TryFrom<NodeInfo> for TapTree {
        type Error = HiddenNodesError;

        /// Constructs [`TapTree`] from a [`NodeInfo`] if it is complete binary tree.
        ///
        /// # Returns
        ///
        /// A [`TapTree`] iff the [`NodeInfo`] has no hidden nodes, otherwise return
        /// [`HiddenNodesError`] error with the content of incomplete [`NodeInfo`] instance.
        fn try_from(node_info: NodeInfo) -> Result<Self, Self::Error> {
            if node_info.has_hidden_nodes {
                Err(HiddenNodesError::HiddenParts(node_info))
            } else {
                Ok(TapTree(node_info))
            }
        }
    }

    /// Iterator for a taproot script tree, operating in DFS order yielding [`ScriptLeaf`].
    ///
    /// Returned by [`TapTree::script_leaves`]. [`TapTree`] does not allow hidden nodes,
    /// so this iterator is guaranteed to yield all known leaves.
    pub struct ScriptLeaves<'tree> {
        leaf_iter: LeafNodes<'tree>,
    }

    impl<'tree> Iterator for ScriptLeaves<'tree> {
        type Item = ScriptLeaf<'tree>;

        #[inline]
        fn next(&mut self) -> Option<Self::Item> {
            ScriptLeaf::from_leaf_node(self.leaf_iter.next()?)
        }

        fn size_hint(&self) -> (usize, Option<usize>) { self.leaf_iter.size_hint() }
    }

    impl<'tree> ExactSizeIterator for ScriptLeaves<'tree> {}

    impl<'tree> FusedIterator for ScriptLeaves<'tree> {}

    impl<'tree> DoubleEndedIterator for ScriptLeaves<'tree> {
        #[inline]
        fn next_back(&mut self) -> Option<Self::Item> {
            ScriptLeaf::from_leaf_node(self.leaf_iter.next_back()?)
        }
    }
    /// Iterator for a taproot script tree, operating in DFS order yielding [`LeafNode`].
    ///
    /// Returned by [`NodeInfo::leaf_nodes`]. This can potentially yield hidden nodes.
    pub struct LeafNodes<'a> {
        leaf_iter: core::slice::Iter<'a, LeafNode>,
    }

    impl<'a> Iterator for LeafNodes<'a> {
        type Item = &'a LeafNode;

        #[inline]
        fn next(&mut self) -> Option<Self::Item> { self.leaf_iter.next() }

        fn size_hint(&self) -> (usize, Option<usize>) { self.leaf_iter.size_hint() }
    }

    impl<'tree> ExactSizeIterator for LeafNodes<'tree> {}

    impl<'tree> FusedIterator for LeafNodes<'tree> {}

    impl<'tree> DoubleEndedIterator for LeafNodes<'tree> {
        #[inline]
        fn next_back(&mut self) -> Option<Self::Item> { self.leaf_iter.next_back() }
    }
    /// Represents the node information in taproot tree. In contrast to [`TapTree`], this
    /// is allowed to have hidden leaves as children.
    ///
    /// Helper type used in merkle tree construction allowing one to build sparse merkle trees. The node
    /// represents part of the tree that has information about all of its descendants.
    /// See how [`TaprootBuilder`] works for more details.
    ///
    /// You can use [`TaprootSpendInfo::from_node_info`] to a get a [`TaprootSpendInfo`] from the merkle
    /// root [`NodeInfo`].
    #[derive(Debug, Clone, PartialOrd, Ord)]
    pub struct NodeInfo {
        /// Merkle hash for this node.
        pub(crate) hash: TapNodeHash,
        /// Information about leaves inside this node.
        pub(crate) leaves: Vec<LeafNode>,
        /// Tracks information on hidden nodes below this node.
        pub(crate) has_hidden_nodes: bool,
    }

    impl PartialEq for NodeInfo {
        fn eq(&self, other: &Self) -> bool { self.hash.eq(&other.hash) }
    }

    impl core::hash::Hash for NodeInfo {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) { self.hash.hash(state) }
    }

    impl Eq for NodeInfo {}

    impl NodeInfo {
        /// Creates a new [`NodeInfo`] with omitted/hidden info.
        pub fn new_hidden_node(hash: TapNodeHash) -> Self {
            Self { hash, leaves: vec![], has_hidden_nodes: true }
        }

        /// Creates a new leaf [`NodeInfo`] with given [`ScriptBuf`] and [`LeafVersion`].
        pub fn new_leaf_with_ver(script: ScriptBuf, ver: LeafVersion) -> Self {
            Self {
                hash: TapNodeHash::from_script(&script, ver),
                leaves: vec![LeafNode::new_script(script, ver)],
                has_hidden_nodes: false,
            }
        }

        /// Combines two [`NodeInfo`] to create a new parent.
        pub fn combine(a: Self, b: Self) -> Result<Self, TaprootBuilderError> {
            let mut all_leaves = Vec::with_capacity(a.leaves.len() + b.leaves.len());
            let (hash, left_first) = TapNodeHash::combine_node_hashes(a.hash, b.hash);
            let (a, b) = if left_first { (a, b) } else { (b, a) };
            for mut a_leaf in a.leaves {
                a_leaf.merkle_branch.push(b.hash)?; // add hashing partner
                all_leaves.push(a_leaf);
            }
            for mut b_leaf in b.leaves {
                b_leaf.merkle_branch.push(a.hash)?; // add hashing partner
                all_leaves.push(b_leaf);
            }
            Ok(Self {
                hash,
                leaves: all_leaves,
                has_hidden_nodes: a.has_hidden_nodes || b.has_hidden_nodes,
            })
        }

        /// Creates an iterator over all leaves (including hidden leaves) in the tree.
        pub fn leaf_nodes(&self) -> LeafNodes { LeafNodes { leaf_iter: self.leaves.iter() } }

        /// Returns the root [`TapNodeHash`] of this node info.
        pub fn node_hash(&self) -> TapNodeHash { self.hash }
    }

    impl TryFrom<TaprootBuilder> for NodeInfo {
        type Error = IncompleteBuilderError;

        fn try_from(builder: TaprootBuilder) -> Result<Self, Self::Error> {
            builder.try_into_node_info()
        }
    }

    #[cfg(feature = "serde")]
    impl serde::Serialize for NodeInfo {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeSeq;
            let mut seq = serializer.serialize_seq(Some(self.leaves.len() * 2))?;
            for tap_leaf in self.leaves.iter() {
                seq.serialize_element(&tap_leaf.merkle_branch().len())?;
                seq.serialize_element(&tap_leaf.leaf)?;
            }
            seq.end()
        }
    }

    #[cfg(feature = "serde")]
    impl<'de> serde::Deserialize<'de> for NodeInfo {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct SeqVisitor;
            impl<'de> serde::de::Visitor<'de> for SeqVisitor {
                type Value = NodeInfo;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("Taproot tree in DFS walk order")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let size = seq
                        .size_hint()
                        .map(|x| core::mem::size_of::<usize>() * 8 - x.leading_zeros() as usize)
                        .map(|x| x / 2) // Each leaf is serialized as two elements.
                        .unwrap_or(0)
                        .min(TAPROOT_CONTROL_MAX_NODE_COUNT); // no more than 128 nodes
                    let mut builder = TaprootBuilder::with_capacity(size);
                    while let Some(depth) = seq.next_element()? {
                        let tap_leaf: TapLeaf = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::custom("Missing tap_leaf"))?;
                        match tap_leaf {
                            TapLeaf::Script(script, ver) => {
                                builder =
                                    builder.add_leaf_with_ver(depth, script, ver).map_err(|e| {
                                        serde::de::Error::custom(format!(
                                            "Leaf insertion error: {}",
                                            e
                                        ))
                                    })?;
                            }
                            TapLeaf::Hidden(h) => {
                                builder = builder.add_hidden_node(depth, h).map_err(|e| {
                                    serde::de::Error::custom(format!(
                                        "Hidden node insertion error: {}",
                                        e
                                    ))
                                })?;
                            }
                        }
                    }
                    NodeInfo::try_from(builder).map_err(|e| {
                        serde::de::Error::custom(format!("Incomplete taproot tree: {}", e))
                    })
                }
            }

            deserializer.deserialize_seq(SeqVisitor)
        }
    }

    /// Leaf node in a taproot tree. Can be either hidden or known.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
    pub enum TapLeaf {
        /// A known script
        Script(ScriptBuf, LeafVersion),
        /// Hidden Node with the given leaf hash
        Hidden(TapNodeHash),
    }

    impl TapLeaf {
        /// Obtains the hidden leaf hash if the leaf is hidden.
        pub fn as_hidden(&self) -> Option<&TapNodeHash> {
            if let Self::Hidden(v) = self {
                Some(v)
            } else {
                None
            }
        }

        /// Obtains a reference to script and version if the leaf is known.
        pub fn as_script(&self) -> Option<(&Script, LeafVersion)> {
            if let Self::Script(script, ver) = self {
                Some((script, *ver))
            } else {
                None
            }
        }
    }

    /// Store information about taproot leaf node.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct LeafNode {
        /// The [`TapLeaf`]
        leaf: TapLeaf,
        /// The merkle proof (hashing partners) to get this node.
        merkle_branch: TaprootMerkleBranch,
    }

    impl LeafNode {
        /// Creates an new [`ScriptLeaf`] from `script` and `ver` and no merkle branch.
        pub fn new_script(script: ScriptBuf, ver: LeafVersion) -> Self {
            Self { leaf: TapLeaf::Script(script, ver), merkle_branch: Default::default() }
        }

        /// Creates an new [`ScriptLeaf`] from `hash` and no merkle branch.
        pub fn new_hidden(hash: TapNodeHash) -> Self {
            Self { leaf: TapLeaf::Hidden(hash), merkle_branch: Default::default() }
        }

        /// Returns the depth of this script leaf in the tap tree.
        #[inline]
        pub fn depth(&self) -> u8 {
            // Depth is guarded by TAPROOT_CONTROL_MAX_NODE_COUNT.
            u8::try_from(self.merkle_branch().len()).expect("depth is guaranteed to fit in a u8")
        }

        /// Computes a leaf hash for this [`ScriptLeaf`] if the leaf is known.
        ///
        /// This [`TapLeafHash`] is useful while signing taproot script spends.
        ///
        /// See [`LeafNode::node_hash`] for computing the [`TapNodeHash`] which returns the hidden node
        /// hash if the node is hidden.
        #[inline]
        pub fn leaf_hash(&self) -> Option<TapLeafHash> {
            let (script, ver) = self.leaf.as_script()?;
            Some(TapLeafHash::from_script(script, ver))
        }

        /// Computes the [`TapNodeHash`] for this [`ScriptLeaf`]. This returns the
        /// leaf hash if the leaf is known and the hidden node hash if the leaf is
        /// hidden.
        /// See also, [`LeafNode::leaf_hash`].
        #[inline]
        pub fn node_hash(&self) -> TapNodeHash {
            match self.leaf {
                TapLeaf::Script(ref script, ver) => TapLeafHash::from_script(script, ver).into(),
                TapLeaf::Hidden(ref hash) => *hash,
            }
        }

        /// Returns reference to the leaf script if the leaf is known.
        #[inline]
        pub fn script(&self) -> Option<&Script> { self.leaf.as_script().map(|x| x.0) }

        /// Returns leaf version of the script if the leaf is known.
        #[inline]
        pub fn leaf_version(&self) -> Option<LeafVersion> { self.leaf.as_script().map(|x| x.1) }

        /// Returns reference to the merkle proof (hashing partners) to get this
        /// node in form of [`TaprootMerkleBranch`].
        #[inline]
        pub fn merkle_branch(&self) -> &TaprootMerkleBranch { &self.merkle_branch }

        /// Returns a reference to the leaf of this [`ScriptLeaf`].
        #[inline]
        pub fn leaf(&self) -> &TapLeaf { &self.leaf }
    }

    impl From<LeafNode> for TapNodeHash {
        fn from(leaf: LeafNode) -> TapNodeHash { leaf.node_hash() }
    }

    impl From<&LeafNode> for TapNodeHash {
        fn from(leaf: &LeafNode) -> TapNodeHash { leaf.node_hash() }
    }

    /// ScriptBuf leaf node in a taproot tree along with the merkle proof to get this node.
    /// Returned by [`TapTree::script_leaves`]
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ScriptLeaf<'leaf> {
        /// The version of the script leaf.
        version: LeafVersion,
        /// The script.
        script: &'leaf Script,
        /// The merkle proof (hashing partners) to get this node.
        merkle_branch: &'leaf TaprootMerkleBranch,
    }

    impl<'leaf> ScriptLeaf<'leaf> {
        /// Obtains the version of the script leaf.
        pub fn version(&self) -> LeafVersion { self.version }

        /// Obtains a reference to the script inside the leaf.
        pub fn script(&self) -> &Script { self.script }

        /// Obtains a reference to the merkle proof of the leaf.
        pub fn merkle_branch(&self) -> &TaprootMerkleBranch { self.merkle_branch }

        /// Obtains a script leaf from the leaf node if the leaf is not hidden.
        pub fn from_leaf_node(leaf_node: &'leaf LeafNode) -> Option<Self> {
            let (script, ver) = leaf_node.leaf.as_script()?;
            Some(Self { version: ver, script, merkle_branch: &leaf_node.merkle_branch })
        }
    }

    /// Control block data structure used in Tapscript satisfaction.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
    pub struct ControlBlock {
        /// The tapleaf version.
        pub leaf_version: LeafVersion,
        /// The parity of the output key (NOT THE INTERNAL KEY WHICH IS ALWAYS XONLY).
        pub output_key_parity: secp256k1::Parity,
        /// The internal key.
        pub internal_key: UntweakedPublicKey,
        /// The merkle proof of a script associated with this leaf.
        pub merkle_branch: TaprootMerkleBranch,
    }

    impl ControlBlock {
        /// Decodes bytes representing a `ControlBlock`.
        ///
        /// This is an extra witness element that provides the proof that taproot script pubkey is
        /// correctly computed with some specified leaf hash. This is the last element in taproot
        /// witness when spending a output via script path.
        ///
        /// # Errors
        ///
        /// - [`TaprootError::InvalidControlBlockSize`] if `sl` is not of size 1 + 32 + 32N for any N >= 0.
        /// - [`TaprootError::InvalidTaprootLeafVersion`] if first byte of `sl` is not a valid leaf version.
        /// - [`TaprootError::InvalidInternalKey`] if internal key is invalid (first 32 bytes after the parity byte).
        /// - [`TaprootError::InvalidMerkleTreeDepth`] if merkle tree is too deep (more than 128 levels).
        pub fn decode(sl: &[u8]) -> Result<ControlBlock, TaprootError> {
            if sl.len() < TAPROOT_CONTROL_BASE_SIZE
                || (sl.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
            {
                return Err(TaprootError::InvalidControlBlockSize(sl.len()));
            }
            let output_key_parity = match sl[0] & 1 {
                0 => secp256k1::Parity::Even,
                _ => secp256k1::Parity::Odd,
            };

            let leaf_version = LeafVersion::from_consensus(sl[0] & TAPROOT_LEAF_MASK)?;
            let internal_key = UntweakedPublicKey::from_slice(&sl[1..TAPROOT_CONTROL_BASE_SIZE])
                .map_err(TaprootError::InvalidInternalKey)?;
            let merkle_branch = TaprootMerkleBranch::decode(&sl[TAPROOT_CONTROL_BASE_SIZE..])?;
            Ok(ControlBlock { leaf_version, output_key_parity, internal_key, merkle_branch })
        }

        /// Returns the size of control block. Faster and more efficient than calling
        /// `Self::serialize().len()`. Can be handy for fee estimation.
        pub fn size(&self) -> usize {
            TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.len()
        }

        /// Serializes to a writer.
        ///
        /// # Returns
        ///
        /// The number of bytes written to the writer.
        pub fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> io::Result<usize> {
            let first_byte: u8 =
                i32::from(self.output_key_parity) as u8 | self.leaf_version.to_consensus();
            writer.write_all(&[first_byte])?;
            writer.write_all(&self.internal_key.serialize())?;
            self.merkle_branch.encode(writer)?;
            Ok(self.size())
        }

        /// Serializes the control block.
        ///
        /// This would be required when using [`ControlBlock`] as a witness element while spending an
        /// output via script path. This serialization does not include the [`crate::VarInt`] prefix that would
        /// be applied when encoding this element as a witness.
        pub fn serialize(&self) -> Vec<u8> {
            let mut buf = Vec::with_capacity(self.size());
            self.encode(&mut buf).expect("writers don't error");
            buf
        }

        /// Verifies that a control block is correct proof for a given output key and script.
        ///
        /// Only checks that script is contained inside the taptree described by output key. Full
        /// verification must also execute the script with witness data.
        pub fn verify_taproot_commitment<C: secp256k1::Verification>(
            &self,
            secp: &Secp256k1<C>,
            output_key: XOnlyPublicKey,
            script: &Script,
        ) -> bool {
            // compute the script hash
            // Initially the curr_hash is the leaf hash
            let mut curr_hash = TapNodeHash::from_script(script, self.leaf_version);
            // Verify the proof
            for elem in &self.merkle_branch {
                // Recalculate the curr hash as parent hash
                curr_hash = TapNodeHash::from_node_hashes(curr_hash, *elem);
            }
            // compute the taptweak
            let tweak =
                TapTweakHash::from_key_and_tweak(self.internal_key, Some(curr_hash)).to_scalar();
            self.internal_key.tweak_add_check(secp, &output_key, self.output_key_parity, tweak)
        }
    }

    /// Detailed error type for taproot builder.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum TaprootBuilderError {
        /// Merkle tree depth must not be more than 128.
        InvalidMerkleTreeDepth(usize),
        /// Nodes must be added specified in DFS walk order.
        NodeNotInDfsOrder,
        /// Two nodes at depth 0 are not allowed.
        OverCompleteTree,
        /// Invalid taproot internal key.
        InvalidInternalKey(secp256k1::Error),
        /// Called finalize on a empty tree.
        EmptyTree,
    }

    internals::impl_from_infallible!(TaprootBuilderError);

    impl fmt::Display for TaprootBuilderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use TaprootBuilderError::*;

            match *self {
                InvalidMerkleTreeDepth(d) => {
                    write!(
                        f,
                        "Merkle Tree depth({}) must be less than {}",
                        d, TAPROOT_CONTROL_MAX_NODE_COUNT
                    )
                }
                NodeNotInDfsOrder => {
                    write!(f, "add_leaf/add_hidden must be called in DFS walk order",)
                }
                OverCompleteTree => write!(
                    f,
                    "Attempted to create a tree with two nodes at depth 0. There must\
                     only be a exactly one node at depth 0",
                ),
                InvalidInternalKey(ref e) => {
                    write_err!(f, "invalid internal x-only key"; e)
                }
                EmptyTree => {
                    write!(f, "Called finalize on an empty tree")
                }
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for TaprootBuilderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use TaprootBuilderError::*;

            match self {
                InvalidInternalKey(e) => Some(e),
                InvalidMerkleTreeDepth(_) | NodeNotInDfsOrder | OverCompleteTree | EmptyTree =>
                    None,
            }
        }
    }

    /// Detailed error type for taproot utilities.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum TaprootError {
        /// Proof size must be a multiple of 32.
        InvalidMerkleBranchSize(usize),
        /// Merkle tree depth must not be more than 128.
        InvalidMerkleTreeDepth(usize),
        /// The last bit of tapleaf version must be zero.
        InvalidTaprootLeafVersion(u8),
        /// Invalid control block size.
        InvalidControlBlockSize(usize),
        /// Invalid taproot internal key.
        InvalidInternalKey(secp256k1::Error),
        /// Empty tap tree.
        EmptyTree,
    }

    internals::impl_from_infallible!(TaprootError);

    impl fmt::Display for TaprootError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use TaprootError::*;

            match *self {
                InvalidMerkleBranchSize(sz) => write!(
                    f,
                    "Merkle branch size({}) must be a multiple of {}",
                    sz, TAPROOT_CONTROL_NODE_SIZE
                ),
                InvalidMerkleTreeDepth(d) => write!(
                    f,
                    "Merkle Tree depth({}) must be less than {}",
                    d, TAPROOT_CONTROL_MAX_NODE_COUNT
                ),
                InvalidTaprootLeafVersion(v) => {
                    write!(f, "Leaf version({}) must have the least significant bit 0", v)
                }
                InvalidControlBlockSize(sz) => write!(
                    f,
                    "Control Block size({}) must be of the form 33 + 32*m where  0 <= m <= {} ",
                    sz, TAPROOT_CONTROL_MAX_NODE_COUNT
                ),
                InvalidInternalKey(ref e) => {
                    write_err!(f, "invalid internal x-only key"; e)
                }
                EmptyTree => write!(f, "Taproot Tree must contain at least one script"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for TaprootError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use TaprootError::*;

            match self {
                InvalidInternalKey(e) => Some(e),
                InvalidMerkleBranchSize(_)
                | InvalidMerkleTreeDepth(_)
                | InvalidTaprootLeafVersion(_)
                | InvalidControlBlockSize(_)
                | EmptyTree => None,
            }
        }
    }

    impl From<super::LeafVersionError> for TaprootError {
        fn from(e: super::LeafVersionError) -> Self { Self::InvalidTaprootLeafVersion(e.0) }
    }
}
