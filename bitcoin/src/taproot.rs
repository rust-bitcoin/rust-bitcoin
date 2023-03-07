// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Taproot.
//!
//! This module provides support for taproot tagged hashes.
//!

use core::cmp::Reverse;
use core::convert::TryFrom;
use core::fmt;
use core::iter::FusedIterator;

use bitcoin_internals::write_err;
use secp256k1::{self, Scalar, Secp256k1};

use crate::consensus::Encodable;
use crate::crypto::key::{TapTweak, TweakedPublicKey, UntweakedPublicKey, XOnlyPublicKey};
// Re-export these so downstream only has to use one `taproot` module.
pub use crate::crypto::taproot::{Error, Signature};
use crate::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use crate::prelude::*;
use crate::{io, Script, ScriptBuf};

/// The SHA-256 midstate value for the TapLeaf hash.
const MIDSTATE_TAPLEAF: [u8; 32] = [
    156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147, 108,
    71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
];
// 9ce0e4e67c116c3938b3caf2c30f5089d3f3936c47636e607db33eeaddc6f0c9

/// The SHA-256 midstate value for the TapBranch hash.
const MIDSTATE_TAPBRANCH: [u8; 32] = [
    35, 168, 101, 169, 184, 164, 13, 167, 151, 124, 30, 4, 196, 158, 36, 111, 181, 190, 19, 118,
    157, 36, 201, 183, 181, 131, 181, 212, 168, 210, 38, 210,
];
// 23a865a9b8a40da7977c1e04c49e246fb5be13769d24c9b7b583b5d4a8d226d2

/// The SHA-256 midstate value for the TapTweak hash.
const MIDSTATE_TAPTWEAK: [u8; 32] = [
    209, 41, 162, 243, 112, 28, 101, 93, 101, 131, 182, 195, 185, 65, 151, 39, 149, 244, 226, 50,
    148, 253, 84, 244, 162, 174, 141, 133, 71, 202, 89, 11,
];
// d129a2f3701c655d6583b6c3b941972795f4e23294fd54f4a2ae8d8547ca590b

// Taproot test vectors from BIP-341 state the hashes without any reversing
#[rustfmt::skip]
sha256t_hash_newtype!(TapLeafHash, TapLeafTag, MIDSTATE_TAPLEAF, 64,
    doc="Taproot-tagged hash with tag \"TapLeaf\".

This is used for computing tapscript script spend hash.", forward
);
#[rustfmt::skip]
sha256t_hash_newtype!(TapNodeHash, TapBranchTag, MIDSTATE_TAPBRANCH, 64,
    doc="Tagged hash used in taproot trees; see BIP-340 for tagging rules", forward
);
#[rustfmt::skip]
sha256t_hash_newtype!(TapTweakHash, TapTweakTag, MIDSTATE_TAPTWEAK, 64,
    doc="Taproot-tagged hash with tag \"TapTweak\".
    This hash type is used while computing the tweaked public key", forward
);

impl TapTweakHash {
    /// Creates a new BIP341 [`TapTweakHash`] from key and tweak. Produces `H_taptweak(P||R)` where
    /// `P` is the internal key and `R` is the merkle root.
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

impl From<LeafNode> for TapNodeHash {
    fn from(leaf: LeafNode) -> TapNodeHash { leaf.node_hash() }
}

impl From<&LeafNode> for TapNodeHash {
    fn from(leaf: &LeafNode) -> TapNodeHash { leaf.node_hash() }
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

    /// Returns the internal script map.
    pub fn as_script_map(&self) -> &ScriptMerkleProofMap { &self.script_map }

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
            .min_by(|x, y| x.0.len().cmp(&y.0.len()))
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

    /// Adds a leaf script at `depth` to the builder with script version `ver`. Errors if the leaves
    /// are not provided in DFS walk order. The depth of the root node is 0.
    pub fn add_leaf_with_ver(
        self,
        depth: u8,
        script: ScriptBuf,
        ver: LeafVersion,
    ) -> Result<Self, TaprootBuilderError> {
        let leaf = NodeInfo::new_leaf_with_ver(script, ver);
        self.insert(leaf, depth)
    }

    /// Adds a leaf script at `depth` to the builder with default script version. Errors if the
    /// leaves are not provided in DFS walk order. The depth of the root node is 0.
    ///
    /// See [`TaprootBuilder::add_leaf_with_ver`] for adding a leaf with specific version.
    pub fn add_leaf(self, depth: u8, script: ScriptBuf) -> Result<Self, TaprootBuilderError> {
        self.add_leaf_with_ver(depth, script, LeafVersion::TapScript)
    }

    /// Adds a hidden/omitted node at `depth` to the builder. Errors if the leaves are not provided
    /// in DFS walk order. The depth of the root node is 0.
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
    /// [`IncompleteBuilder::NotFinalized`] if the builder is not finalized. The builder
    /// can be restored by calling [`IncompleteBuilder::into_builder`]
    pub fn try_into_node_info(mut self) -> Result<NodeInfo, IncompleteBuilder> {
        if self.branch().len() != 1 {
            return Err(IncompleteBuilder::NotFinalized(self));
        }
        Ok(self
            .branch
            .pop()
            .expect("length checked above")
            .expect("invariant guarantees node info exists"))
    }

    /// Converts the builder into a [`TapTree`] if the builder is a full tree and
    /// does not contain any hidden nodes
    pub fn try_into_taptree(self) -> Result<TapTree, IncompleteBuilder> {
        let node = self.try_into_node_info()?;
        if node.has_hidden_nodes {
            // Reconstruct the builder as it was if it has hidden nodes
            return Err(IncompleteBuilder::HiddenParts(TaprootBuilder {
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
                    unreachable!("Size checked above. Builder guarantees the last element is Some")
                },
            _ => Err(self),
        }
    }

    pub(crate) fn branch(&self) -> &[Option<NodeInfo>] { &self.branch }

    /// Inserts a leaf at `depth`.
    fn insert(mut self, mut node: NodeInfo, mut depth: u8) -> Result<Self, TaprootBuilderError> {
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
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum IncompleteBuilder {
    /// Indicates an attempt to construct a tap tree from a builder containing incomplete branches.
    NotFinalized(TaprootBuilder),
    /// Indicates an attempt to construct a tap tree from a builder containing hidden parts.
    HiddenParts(TaprootBuilder),
}

impl IncompleteBuilder {
    /// Converts error into the original incomplete [`TaprootBuilder`] instance.
    pub fn into_builder(self) -> TaprootBuilder {
        match self {
            IncompleteBuilder::NotFinalized(builder) | IncompleteBuilder::HiddenParts(builder) =>
                builder,
        }
    }
}

impl core::fmt::Display for IncompleteBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            IncompleteBuilder::NotFinalized(_) =>
                "an attempt to construct a tap tree from a builder containing incomplete branches.",
            IncompleteBuilder::HiddenParts(_) =>
                "an attempt to construct a tap tree from a builder containing hidden parts.",
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for IncompleteBuilder {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::IncompleteBuilder::*;

        match self {
            NotFinalized(_) | HiddenParts(_) => None,
        }
    }
}

/// Error happening when [`TapTree`] is constructed from a [`NodeInfo`]
/// having hidden branches.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum HiddenNodes {
    /// Indicates an attempt to construct a tap tree from a builder containing hidden parts.
    HiddenParts(NodeInfo),
}

impl HiddenNodes {
    /// Converts error into the original incomplete [`NodeInfo`] instance.
    pub fn into_node_info(self) -> NodeInfo {
        match self {
            HiddenNodes::HiddenParts(node_info) => node_info,
        }
    }
}

impl core::fmt::Display for HiddenNodes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HiddenNodes::HiddenParts(_) =>
                "an attempt to construct a tap tree from a node_info containing hidden parts.",
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for HiddenNodes {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::HiddenNodes::*;

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
    pub fn script_leaves(&self) -> ScriptLeaves { ScriptLeaves { leaf_iter: self.0.leaf_nodes() } }
}

impl TryFrom<TaprootBuilder> for TapTree {
    type Error = IncompleteBuilder;

    /// Constructs [`TapTree`] from a [`TaprootBuilder`] if it is complete binary tree.
    ///
    /// # Returns
    ///
    /// A [`TapTree`] iff the `builder` is complete, otherwise return [`IncompleteBuilder`]
    /// error with the content of incomplete `builder` instance.
    fn try_from(builder: TaprootBuilder) -> Result<Self, Self::Error> { builder.try_into_taptree() }
}

impl TryFrom<NodeInfo> for TapTree {
    type Error = HiddenNodes;

    /// Constructs [`TapTree`] from a [`NodeInfo`] if it is complete binary tree.
    ///
    /// # Returns
    ///
    /// A [`TapTree`] iff the [`NodeInfo`] has no hidden nodes, otherwise return [`HiddenNodes`]
    /// error with the content of incomplete [`NodeInfo`] instance.
    fn try_from(node_info: NodeInfo) -> Result<Self, Self::Error> {
        if node_info.has_hidden_nodes {
            Err(HiddenNodes::HiddenParts(node_info))
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
    fn next(&mut self) -> Option<Self::Item> { ScriptLeaf::from_leaf_node(self.leaf_iter.next()?) }

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
}

impl TryFrom<TaprootBuilder> for NodeInfo {
    type Error = IncompleteBuilder;

    fn try_from(builder: TaprootBuilder) -> Result<Self, Self::Error> {
        builder.try_into_node_info()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
                                    serde::de::Error::custom(format!("Leaf insertion error: {}", e))
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
        Self { leaf: TapLeaf::Script(script, ver), merkle_branch: TaprootMerkleBranch(vec![]) }
    }

    /// Creates an new [`ScriptLeaf`] from `hash` and no merkle branch.
    pub fn new_hidden(hash: TapNodeHash) -> Self {
        Self { leaf: TapLeaf::Hidden(hash), merkle_branch: TaprootMerkleBranch(vec![]) }
    }

    /// Returns the depth of this script leaf in the tap tree.
    #[inline]
    pub fn depth(&self) -> u8 {
        // Depth is guarded by TAPROOT_CONTROL_MAX_NODE_COUNT.
        u8::try_from(self.merkle_branch().0.len()).expect("depth is guaranteed to fit in a u8")
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

/// Script leaf node in a taproot tree along with the merkle proof to get this node.
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

/// The merkle proof for inclusion of a tree in a taptree hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(into = "Vec<TapNodeHash>"))]
#[cfg_attr(feature = "serde", serde(try_from = "Vec<TapNodeHash>"))]
pub struct TaprootMerkleBranch(Vec<TapNodeHash>);

impl TaprootMerkleBranch {
    /// Returns a reference to the inner vector of hashes.
    pub fn as_inner(&self) -> &[TapNodeHash] { &self.0 }

    /// Returns the number of nodes in this merkle proof.
    pub fn len(&self) -> usize { self.0.len() }

    /// Checks if this merkle proof is empty.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Decodes bytes from control block.
    #[deprecated(since = "0.30.0", note = "Use decode instead")]
    pub fn from_slice(sl: &[u8]) -> Result<Self, TaprootError> { Self::decode(sl) }

    /// Decodes bytes from control block.
    ///
    /// This reads the branch as encoded in the control block: the concatenated 32B byte chunks -
    /// one for each hash.
    ///
    /// # Errors
    ///
    /// The function returns an error if the the number of bytes is not an integer multiple of 32 or
    /// if the number of hashes exceeds 128.
    pub fn decode(sl: &[u8]) -> Result<Self, TaprootError> {
        if sl.len() % TAPROOT_CONTROL_NODE_SIZE != 0 {
            Err(TaprootError::InvalidMerkleBranchSize(sl.len()))
        } else if sl.len() > TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(sl.len() / TAPROOT_CONTROL_NODE_SIZE))
        } else {
            let inner = sl
                .chunks_exact(TAPROOT_CONTROL_NODE_SIZE)
                .map(|chunk| {
                    TapNodeHash::from_slice(chunk)
                        .expect("chunks_exact always returns the correct size")
                })
                .collect();

            Ok(TaprootMerkleBranch(inner))
        }
    }

    /// Creates a merkle proof from list of hashes.
    ///
    /// # Errors
    /// If inner proof length is more than [`TAPROOT_CONTROL_MAX_NODE_COUNT`] (128).
    fn from_collection<T: AsRef<[TapNodeHash]> + Into<Vec<TapNodeHash>>>(
        collection: T,
    ) -> Result<Self, TaprootError> {
        if collection.as_ref().len() > TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(collection.as_ref().len()))
        } else {
            Ok(TaprootMerkleBranch(collection.into()))
        }
    }

    /// Serializes to a writer.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the writer.
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        for hash in self.0.iter() {
            writer.write_all(hash.as_ref())?;
        }
        Ok(self.0.len() * TapNodeHash::LEN)
    }

    /// Serializes `self` as bytes.
    pub fn serialize(&self) -> Vec<u8> {
        self.0.iter().flat_map(|e| e.as_byte_array()).copied().collect::<Vec<u8>>()
    }

    /// Appends elements to proof.
    fn push(&mut self, h: TapNodeHash) -> Result<(), TaprootBuilderError> {
        if self.0.len() >= TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootBuilderError::InvalidMerkleTreeDepth(self.0.len()))
        } else {
            self.0.push(h);
            Ok(())
        }
    }

    /// Returns the inner list of hashes.
    pub fn into_inner(self) -> Vec<TapNodeHash> { self.0 }
}

macro_rules! impl_try_from {
    ($from:ty) => {
        impl TryFrom<$from> for TaprootMerkleBranch {
            type Error = TaprootError;

            /// Creates a merkle proof from list of hashes.
            ///
            /// # Errors
            /// If inner proof length is more than [`TAPROOT_CONTROL_MAX_NODE_COUNT`] (128).
            fn try_from(v: $from) -> Result<Self, Self::Error> {
                TaprootMerkleBranch::from_collection(v)
            }
        }
    };
}
impl_try_from!(&[TapNodeHash]);
impl_try_from!(Vec<TapNodeHash>);
impl_try_from!(Box<[TapNodeHash]>);

macro_rules! impl_try_from_array {
    ($($len:expr),* $(,)?) => {
        $(
            impl From<[TapNodeHash; $len]> for TaprootMerkleBranch {
                fn from(a: [TapNodeHash; $len]) -> Self {
                    Self(a.to_vec())
                }
            }
        )*
    }
}
// Implement for all values [0, 128] inclusive.
//
// The reason zero is included is that `TaprootMerkleBranch` doesn't contain the hash of the node
// that's being proven - it's not needed because the script is already right before control block.
impl_try_from_array!(
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128
);

impl From<TaprootMerkleBranch> for Vec<TapNodeHash> {
    fn from(branch: TaprootMerkleBranch) -> Self { branch.0 }
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
    /// Constructs a `ControlBlock` from slice.
    #[deprecated(since = "0.30.0", note = "Use decode instead")]
    pub fn from_slice(sl: &[u8]) -> Result<ControlBlock, TaprootError> { Self::decode(sl) }

    /// Decodes bytes representing a `ControlBlock`.
    ///
    /// This is an extra witness element that provides the proof that taproot script pubkey is
    /// correctly computed with some specified leaf hash. This is the last element in taproot
    /// witness when spending a output via script path.
    ///
    /// # Errors
    ///
    /// - [`TaprootError::InvalidControlBlockSize`] if `sl` is not of size 1 + 32 + 32N for any N >= 0.
    /// - [`TaprootError::InvalidParity`] if first byte of `sl` is not a valid output key parity.
    /// - [`TaprootError::InvalidTaprootLeafVersion`] if first byte of `sl` is not a valid leaf version.
    /// - [`TaprootError::InvalidInternalKey`] if internal key is invalid (first 32 bytes after the parity byte).
    /// - [`TaprootError::InvalidMerkleTreeDepth`] if merkle tree is too deep (more than 128 levels).
    pub fn decode(sl: &[u8]) -> Result<ControlBlock, TaprootError> {
        if sl.len() < TAPROOT_CONTROL_BASE_SIZE
            || (sl.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(TaprootError::InvalidControlBlockSize(sl.len()));
        }
        let output_key_parity =
            secp256k1::Parity::from_i32((sl[0] & 1) as i32).map_err(TaprootError::InvalidParity)?;
        let leaf_version = LeafVersion::from_consensus(sl[0] & TAPROOT_LEAF_MASK)?;
        let internal_key = UntweakedPublicKey::from_slice(&sl[1..TAPROOT_CONTROL_BASE_SIZE])
            .map_err(TaprootError::InvalidInternalKey)?;
        let merkle_branch = TaprootMerkleBranch::decode(&sl[TAPROOT_CONTROL_BASE_SIZE..])?;
        Ok(ControlBlock { leaf_version, output_key_parity, internal_key, merkle_branch })
    }

    /// Returns the size of control block. Faster and more efficient than calling
    /// `Self::serialize().len()`. Can be handy for fee estimation.
    pub fn size(&self) -> usize {
        TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.as_inner().len()
    }

    /// Serializes to a writer.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the writer.
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        let first_byte: u8 =
            i32::from(self.output_key_parity) as u8 | self.leaf_version.to_consensus();
        writer.write_all(&[first_byte])?;
        writer.write_all(&self.internal_key.serialize())?;
        self.merkle_branch.encode(&mut writer)?;
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
        for elem in self.merkle_branch.as_inner() {
            // Recalculate the curr hash as parent hash
            curr_hash = TapNodeHash::from_node_hashes(curr_hash, *elem);
        }
        // compute the taptweak
        let tweak =
            TapTweakHash::from_key_and_tweak(self.internal_key, Some(curr_hash)).to_scalar();
        self.internal_key.tweak_add_check(secp, &output_key, self.output_key_parity, tweak)
    }
}

/// Inner type representing future (non-tapscript) leaf versions. See [`LeafVersion::Future`].
///
/// NB: NO PUBLIC CONSTRUCTOR!
/// The only way to construct this is by converting `u8` to [`LeafVersion`] and then extracting it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FutureLeafVersion(u8);

impl FutureLeafVersion {
    pub(self) fn from_consensus(version: u8) -> Result<FutureLeafVersion, TaprootError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => unreachable!(
                "FutureLeafVersion::from_consensus should be never called for 0xC0 value"
            ),
            TAPROOT_ANNEX_PREFIX =>
                Err(TaprootError::InvalidTaprootLeafVersion(TAPROOT_ANNEX_PREFIX)),
            odd if odd & 0xFE != odd => Err(TaprootError::InvalidTaprootLeafVersion(odd)),
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
    pub fn from_consensus(version: u8) -> Result<Self, TaprootError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => Ok(LeafVersion::TapScript),
            TAPROOT_ANNEX_PREFIX =>
                Err(TaprootError::InvalidTaprootLeafVersion(TAPROOT_ANNEX_PREFIX)),
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
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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

/// Detailed error type for taproot builder.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl fmt::Display for TaprootBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaprootBuilderError::InvalidMerkleTreeDepth(d) => {
                write!(
                    f,
                    "Merkle Tree depth({}) must be less than {}",
                    d, TAPROOT_CONTROL_MAX_NODE_COUNT
                )
            }
            TaprootBuilderError::NodeNotInDfsOrder => {
                write!(f, "add_leaf/add_hidden must be called in DFS walk order",)
            }
            TaprootBuilderError::OverCompleteTree => write!(
                f,
                "Attempted to create a tree with two nodes at depth 0. There must\
                only be a exactly one node at depth 0",
            ),
            TaprootBuilderError::InvalidInternalKey(ref e) => {
                write_err!(f, "invalid internal x-only key"; e)
            }
            TaprootBuilderError::EmptyTree => {
                write!(f, "Called finalize on an empty tree")
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for TaprootBuilderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::TaprootBuilderError::*;

        match self {
            InvalidInternalKey(e) => Some(e),
            InvalidMerkleTreeDepth(_) | NodeNotInDfsOrder | OverCompleteTree | EmptyTree => None,
        }
    }
}

/// Detailed error type for taproot utilities.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Invalid parity for internal key.
    InvalidParity(secp256k1::InvalidParityValue),
    /// Empty tap tree.
    EmptyTree,
}

impl fmt::Display for TaprootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaprootError::InvalidMerkleBranchSize(sz) => write!(
                f,
                "Merkle branch size({}) must be a multiple of {}",
                sz, TAPROOT_CONTROL_NODE_SIZE
            ),
            TaprootError::InvalidMerkleTreeDepth(d) => write!(
                f,
                "Merkle Tree depth({}) must be less than {}",
                d, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            TaprootError::InvalidTaprootLeafVersion(v) => {
                write!(f, "Leaf version({}) must have the least significant bit 0", v)
            }
            TaprootError::InvalidControlBlockSize(sz) => write!(
                f,
                "Control Block size({}) must be of the form 33 + 32*m where  0 <= m <= {} ",
                sz, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            TaprootError::InvalidInternalKey(ref e) => {
                write_err!(f, "invalid internal x-only key"; e)
            }
            TaprootError::InvalidParity(_) => write!(f, "invalid parity value for internal key"),
            TaprootError::EmptyTree => write!(f, "Taproot Tree must contain at least one script"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for TaprootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::TaprootError::*;

        match self {
            InvalidInternalKey(e) => Some(e),
            InvalidMerkleBranchSize(_)
            | InvalidMerkleTreeDepth(_)
            | InvalidTaprootLeafVersion(_)
            | InvalidControlBlockSize(_)
            | InvalidParity(_)
            | EmptyTree => None,
        }
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use secp256k1::{VerifyOnly, XOnlyPublicKey};

    use super::*;
    use crate::hashes::hex::FromHex;
    use crate::hashes::sha256t::Tag;
    use crate::hashes::{sha256, Hash, HashEngine};
    use crate::sighash::{TapSighash, TapSighashTag};
    use crate::{Address, Network};
    extern crate serde_json;

    #[cfg(feature = "serde")]
    use {
        crate::internal_macros::hex,
        serde_test::Configure,
        serde_test::{assert_tokens, Token},
    };

    fn tag_engine(tag_name: &str) -> sha256::HashEngine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
        engine.input(tag_hash.as_ref());
        engine.input(tag_hash.as_ref());
        engine
    }

    #[test]
    fn test_midstates() {
        use crate::crypto::sighash::MIDSTATE_TAPSIGHASH;

        // check midstate against hard-coded values
        assert_eq!(MIDSTATE_TAPLEAF, tag_engine("TapLeaf").midstate().to_byte_array());
        assert_eq!(MIDSTATE_TAPBRANCH, tag_engine("TapBranch").midstate().to_byte_array());
        assert_eq!(MIDSTATE_TAPTWEAK, tag_engine("TapTweak").midstate().to_byte_array());
        assert_eq!(MIDSTATE_TAPSIGHASH, tag_engine("TapSighash").midstate().to_byte_array());

        // test that engine creation roundtrips
        assert_eq!(tag_engine("TapLeaf").midstate(), TapLeafTag::engine().midstate());
        assert_eq!(tag_engine("TapBranch").midstate(), TapBranchTag::engine().midstate());
        assert_eq!(tag_engine("TapTweak").midstate(), TapTweakTag::engine().midstate());
        assert_eq!(tag_engine("TapSighash").midstate(), TapSighashTag::engine().midstate());

        // check that hash creation is the same as building into the same engine
        fn empty_hash(tag_name: &str) -> [u8; 32] {
            let mut e = tag_engine(tag_name);
            e.input(&[]);
            TapNodeHash::from_engine(e).to_byte_array()
        }
        assert_eq!(empty_hash("TapLeaf"), TapLeafHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapBranch"), TapNodeHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapTweak"), TapTweakHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapSighash"), TapSighash::hash(&[]).to_byte_array());
    }

    #[test]
    fn test_vectors_core() {
        //! Test vectors taken from Core

        // uninitialized writers
        //   CHashWriter writer = HasherTapLeaf;
        //   writer.GetSHA256().GetHex()
        assert_eq!(
            TapLeafHash::from_engine(TapLeafTag::engine()).to_string(),
            "5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb"
        );
        assert_eq!(
            TapNodeHash::from_engine(TapBranchTag::engine()).to_string(),
            "53c373ec4d6f3c53c1f5fb2ff506dcefe1a0ed74874f93fa93c8214cbe9ffddf"
        );
        assert_eq!(
            TapTweakHash::from_engine(TapTweakTag::engine()).to_string(),
            "8aa4229474ab0100b2d6f0687f031d1fc9d8eef92a042ad97d279bff456b15e4"
        );
        assert_eq!(
            TapSighash::from_engine(TapSighashTag::engine()).to_string(),
            "dabc11914abcd8072900042a2681e52f8dba99ce82e224f97b5fdb7cd4b9c803"
        );

        // 0-byte
        //   CHashWriter writer = HasherTapLeaf;
        //   writer << std::vector<unsigned char>{};
        //   writer.GetSHA256().GetHex()
        // Note that Core writes the 0 length prefix when an empty vector is written.
        assert_eq!(
            TapLeafHash::hash(&[0]).to_string(),
            "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829"
        );
        assert_eq!(
            TapNodeHash::hash(&[0]).to_string(),
            "92534b1960c7e6245af7d5fda2588db04aa6d646abc2b588dab2b69e5645eb1d"
        );
        assert_eq!(
            TapTweakHash::hash(&[0]).to_string(),
            "cd8737b5e6047fc3f16f03e8b9959e3440e1bdf6dd02f7bb899c352ad490ea1e"
        );
        assert_eq!(
            TapSighash::hash(&[0]).to_string(),
            "c2fd0de003889a09c4afcf676656a0d8a1fb706313ff7d509afb00c323c010cd"
        );
    }

    fn _verify_tap_commitments(
        secp: &Secp256k1<VerifyOnly>,
        out_spk_hex: &str,
        script_hex: &str,
        control_block_hex: &str,
    ) {
        let out_pk = XOnlyPublicKey::from_str(&out_spk_hex[4..]).unwrap();
        let out_pk = TweakedPublicKey::dangerous_assume_tweaked(out_pk);
        let script = ScriptBuf::from_hex(script_hex).unwrap();
        let control_block =
            ControlBlock::decode(&Vec::<u8>::from_hex(control_block_hex).unwrap()).unwrap();
        assert_eq!(control_block_hex, control_block.serialize().to_lower_hex_string());
        assert!(control_block.verify_taproot_commitment(secp, out_pk.to_inner(), &script));
    }

    #[test]
    fn control_block_verify() {
        let secp = Secp256k1::verification_only();
        // test vectors obtained from printing values in feature_taproot.py from Bitcoin Core
        _verify_tap_commitments(&secp, "51205dc8e62b15e0ebdf44751676be35ba32eed2e84608b290d4061bbff136cd7ba9", "6a", "c1a9d6f66cd4b25004f526bfa873e56942f98e8e492bd79ed6532b966104817c2bda584e7d32612381cf88edc1c02e28a296e807c16ad22f591ee113946e48a71e0641e660d1e5392fb79d64838c2b84faf04b7f5f283c9d8bf83e39e177b64372a0cd22eeab7e093873e851e247714eff762d8a30be699ba4456cfe6491b282e193a071350ae099005a5950d74f73ba13077a57bc478007fb0e4d1099ce9cf3d4");
        _verify_tap_commitments(&secp, "5120e208c869c40d8827101c5ad3238018de0f3f5183d77a0c53d18ac28ddcbcd8ad", "f4", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40090ab1f4890d51115998242ebce636efb9ede1b516d9eb8952dc1068e0335306199aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4da14e029b1e154a85bfd9139e7aa2720b6070a4ceba8264ca61d5d3ac27aceb9ef4b54cd43c2d1fd5e11b5c2e93cf29b91ea3dc5b832201f02f7473a28c63246");
        _verify_tap_commitments(
            &secp,
            "5120567666e7df90e0450bb608e17c01ed3fbcfa5355a5f8273e34e583bfaa70ce09",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ac",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(&secp, "5120580a19e47269414a55eb86d5d0c6c9b371455d9fd2154412a57dec840df99fe1", "6a", "bca0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40042ba1bd1c63c03ccff60d4c4d53a653f87909eb3358e7fa45c9d805231fb08c933e1f4e0f9d17f591df1419df7d5b7eb5f744f404c5ef9ecdb1b89b18cafa3a816d8b5dba3205f9a9c05f866d91f40d2793a7586d502cb42f46c7a11f66ad4aa");
        _verify_tap_commitments(&secp, "5120228b94a4806254a38d6efa8a134c28ebc89546209559dfe40b2b0493bafacc5b", "6a50", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4009c9aed3dfd11ab0e78bf87ef3bf296269dc4b0f7712140386d6980992bab4b45");
        _verify_tap_commitments(
            &secp,
            "5120567666e7df90e0450bb608e17c01ed3fbcfa5355a5f8273e34e583bfaa70ce09",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ac",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(
            &secp,
            "5120b0a79103c31fe51eea61d2873bad8a25a310da319d7e7a85f825fa7a00ea3f85",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ad51",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(&secp, "5120f2f62e854a0012aeba78cd4ba4a0832447a5262d4c6eb4f1c95c7914b536fc6c", "6a86", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4009ad3d30479f0689dbdf59a6b840d60ad485b2effbed1825a75ce19a44e460e09056f60ea686d79cfa4fb79f197b2e905ac857a983be4a5a41a4873e865aa950780c0237de279dc063e67deec46ef8e1bc351bf12c4d67a6d568001faf097e797e6ee620f53cfe0f8acaddf2063c39c3577853bb46d61ffcba5a024c3e1216837");
        _verify_tap_commitments(&secp, "51202a4772070b49bae68b44315032cdbf9c40c7c2f896781b32b931b73dbfb26d7e", "6af8", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4006f183944a14618fc7fe9ceade0f58e43a19d3c3b179ea6c43c29616413b6971c99aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4c3462adec78cd04f3cc156bdadec50def99feae0dc6a23664e8a2b0d42d6ca9eb968dfdf46c23af642b2688351904e0a0630e71ffac5bcaba33b9b2c8a7495ec");
        _verify_tap_commitments(&secp, "5120a32b0b8cfafe0f0f8d5870030ba4d19a8725ad345cb3c8420f86ac4e0dff6207", "4c", "e8a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400615da7ac8d078e5fc7f4690fc2127ba40f0f97cc070ade5b3a7919783d91ef3f13734aab908ae998e57848a01268fe8217d70bc3ee8ea8ceae158ae964a4b5f3af20b50d7019bf47fde210eee5c52f1cfe71cfca78f2d3e7c1fd828c80351525");
        _verify_tap_commitments(
            &secp,
            "5120b0a79103c31fe51eea61d2873bad8a25a310da319d7e7a85f825fa7a00ea3f85",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ad51",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(&secp, "51208678459f1fa0f80e9b89b8ffdcaf46a022bdf60aa45f1fed9a96145edf4ec400", "6a50", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4001eff29e1a89e650076b8d3c56302881d09c9df215774ed99993aaed14acd6615");
        _verify_tap_commitments(&secp, "5120017316303aed02bcdec424c851c9eacbe192b013139bd9634c4e19b3475b06e1", "61", "02a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40050462265ca552b23cbb4fe021b474313c8cb87d4a18b3f7bdbeb2b418279ba31fc6509d829cd42336f563363cb3538d78758e0876c71e13012eb2b656eb0edb051a2420a840d5c8c6c762abc7410af2c311f606b20ca2ace56a8139f84b1379a");
        _verify_tap_commitments(&secp, "5120896d4d5d2236e86c6e9320e86d1a7822e652907cbd508360e8c71aefc127c77d", "61", "14a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4001ab0e9d9a4858a0e69605fe9c5a42d739fbe26fa79650e7074f462b02645f7ea1c91802b298cd91e6b5af57c6a013d93397cd2ecbd5569382cc27becf44ff4fff8960b20f846160c159c58350f6b6072cf1b3daa5185b7a42524fb72cbc252576ae46732b8e31ac24bfa7d72f4c3713e8696f99d8ac6c07e4c820a03f249f144");
        _verify_tap_commitments(&secp, "512093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51", "04ffffffff203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ba04feffffff87ab", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400c9a5cd1f6c8a81f5648e39f9810591df1c9a8f1fe97c92e03ecd7c0c016c951983e05473c6e8238cb4c780ea2ce62552b2a3eee068ceffc00517cd7b97e10dad");
        _verify_tap_commitments(&secp, "5120b28d75a7179de6feb66b8bb0bfa2b2c739d1a41cf7366a1b393804a844db8a28", "61", "c4a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400eebc95ded88fb8050094e8dfa958c3be0894eaff0fafae678206b26918d8d7ac47039d40fe34d04b4155df7f1be7f2a49253c7e87812ea9e569e683ac27459e652d6503aa32d64734d00adfee8798b2eed28858abf3bd038e8fa58eb7df4a2d9");
        _verify_tap_commitments(&secp, "512043e4aa733fc6f43c78a31c2b3c192623acf5cc8c01199ebcc4de88067baca83e", "bd4c", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4003f7be6f8848b5bddf332c4d7bd83077f73701e2479f70e02b5730e841234d082b8b41ebea96ffd937715d9faeaa6895e6ef3b22919c554b75df12b3371d328023e443d1df50634ecc1cd169803a1e546f0d44304d8fc5056c408e597fed469b8437d6660eaad3cf72e35ba6e5ff7ddd5e293c1e7e813c871df4f46508e9946ec");
        _verify_tap_commitments(&secp, "5120ee9aecb28f5f35ce1f8b5ec80275ac0f81bca4a21b29b4632fb4bcbef8823e6a", "2021a5981b13be29c9d4ea179ea44a8b773ea8c02d68f6f6eefd98de20d4bd055fac", "c13359c284c196b6e80f0cf1d93b6a397cf7ee722f0427b705bd954b88ada8838bd2622fd0e104fc50aa763b43c6a792d7d117029983abd687223b4344a9402c618bba7f5fc3fa8a57491f6842acde88c1e675ca35caea3b1a69ee2c2d9b10f615");
        _verify_tap_commitments(&secp, "5120885274df2252b44764dcef53c21f21154e8488b7e79fafbc96b9ebb22ad0200d", "6a50", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4000793597254158918e3369507f2d6fdbef17d18b1028bbb0719450ded0f42c58f");
        _verify_tap_commitments(&secp, "512066f6f6f91d47674d198a28388e1eb05ec24e6ddbba10f16396b1a80c08675121", "6a50", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400fe92aff70a2e8e2a4f34a913b99612468a41e0f8ecaff9a729a173d11013c27e");
        _verify_tap_commitments(&secp, "5120868ed9307bd4637491ff03e3aa2c216a08fe213cac8b6cedbb9ab31dbfa6512c", "61", "a2a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400da584e7d32612381cf88edc1c02e28a296e807c16ad22f591ee113946e48a71e46c7eccffefd2d573ec014130e508f0c9963ccebd7830409f7b1b1301725e9fa759d4ef857ec8e0bb42d6d31609d3c7e77de3bfa28c38f93393a6ddbabe819ec560ed4f061fbe742a5fd2a648d5209469420434c8753da3fa7067cc2bb4c172a");
        _verify_tap_commitments(&secp, "5120c1a00a9baa82888fd7d30291135a7eaa9e9966a5f16db2b10460572f8b108d8d", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "5ba0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4007960d7b37dd1361aee34510e77acb4d27ddca17648a17e28475032538c1eb500f5a747f2c0893f79fe153ae918ac3d696de9322aa679aae62051ff5ed83aa502b338bd907346abd4cd9cf06117cb35d55a5a8dd950843522f8de7b5c7fba1804c38b0778d3d76b383f6db6fdf9d6e770da8fffbfa5152c0b8b38129885bcdee6");
        _verify_tap_commitments(&secp, "5120bb9abeff7286b76dfc61800c548fe2621ff47506e47201a85c543b4a9a96fead", "75203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf47342796ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6eadac", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4003eb5cdc419e0a6a800f34583ce750f387be34879c26f4230991bd61da743ad9d34d288e79397b709ac22ad8cc57645d593af3e15b97a876362117177ab2519c000000000000000000000000000000000000000000000000000000000000000007160c3a48c8b17bc3aeaf01db9e0a96ac47a5a9fa329e046856e7765e89c8a93ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07feb9aa7cd72c78e66a85414cd19289f8b0ab1415013dc2a007666aa9248ec1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fccc8bea662a9442a94f7ba0643c1d7ee7cc689f3b3506b7c8c99fd3f3b3d7772972dcdf2550cf95b65098aea67f72fef10abdcf1cef9815af8f4c4644b060e0000000000000000000000000000000000000000000000000000000000000000");
        _verify_tap_commitments(&secp, "5120afddc189ea51094b4cbf463806792e9c8b35dfdc5e01228c78376380d0046b00", "4d09024747703eb9f759ce5ecd839109fecc40974ab16f5173ea390daaa5a78f7abe898165c90990062af998c5dc7989818393158a2c62b7ece727e7f5400d2efd33db8732599f6d1dce6b5b68d2d47317f2de6c9df118f61227f98453225036618aaf058140f2415d134fa69ba041c724ad81387f8c568d12ddc49eb32a71532096181b3f85fd465b8e9a176bb19f45c070baad47a2cc4505414b88c31cb5b0a192b2d2d56c404a37070b04d42c875c4ac351224f5b254f9ad0b820f43cad292d6565f796bf083173e14723f1e543c85a61689ddd5cb6666b240c15c38ce3320bf0c3be9e0322e5ef72366c294d3a2d7e8b8e7db875e7ae814537554f10b91c72b8b413e026bd5d5e917de4b54fa8f43f38771a7f242aa32dcb7ca1b0588dbf54af7ab9455047fbb894cdfdd242166db784276430eb47d4df092a6b8cb160eb982fe7d14a44283bdb4a9861ca65c06fd8b2546cfbfe38bc77f527de1b9bfd2c95a3e283b7b1d1d2b2fa291256a90a7003aefcef47ceabf113865a494af43e96a38b0b00919855eb7722ea2363e0ddfc9c51c08631d01e2a2d56e786b4ff6f1e5d415facc9c2619c285d9ad43001878294157cb025f639fb954271fd1d6173f6bc16535672f6abdd72b0284b4ff3eaf5b7247719d7c39365622610efae6562bef6e08a0b370fba75bb04dbdb90a482d8417e057f8bd021ea6ac32d0d48b08be9f77833b11e5e739960c9837d7583", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400ff698adfda0327f188e2ee35f7aecc0f90c9138a350d450648d968c2b5dd7ef94ddd3ec418dc0d03ee4956feb708d838ed2b20e5a193465a6a1467fd3054e1ea141ea4c4c503a6271e19a090e2a69a24282e3be04c4f98720f7a0eb274d9693d13a8e3c139aa625fa2aefd09854570527f9ac545bda1b689719f5cb715612c07");
        _verify_tap_commitments(&secp, "5120afddc189ea51094b4cbf463806792e9c8b35dfdc5e01228c78376380d0046b00", "83", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4007388cda01113397d4cd00bcfbd08fd68c3cfe3a42cbfe3a7651c1d5e6dacf1ad99aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4b59764bec92507e4a4c3f01a06f05980163ca10f1c549bfe01f85fa4f109a1295e607f5ed9f1008048474de336f11f67a1fbf2012f58944dede0ab19a3ca81f5");
        _verify_tap_commitments(&secp, "512093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51", "04ffffffff203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ba04feffffff87ab", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400c9a5cd1f6c8a81f5648e39f9810591df1c9a8f1fe97c92e03ecd7c0c016c951983e05473c6e8238cb4c780ea2ce62552b2a3eee068ceffc00517cd7b97e10dad");
    }

    #[test]
    fn build_huffman_tree() {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str(
            "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        )
        .unwrap();

        let script_weights = vec![
            (10, ScriptBuf::from_hex("51").unwrap()), // semantics of script don't matter for this test
            (20, ScriptBuf::from_hex("52").unwrap()),
            (20, ScriptBuf::from_hex("53").unwrap()),
            (30, ScriptBuf::from_hex("54").unwrap()),
            (19, ScriptBuf::from_hex("55").unwrap()),
        ];
        let tree_info =
            TaprootSpendInfo::with_huffman_tree(&secp, internal_key, script_weights.clone())
                .unwrap();

        /* The resulting tree should put the scripts into a tree similar
         * to the following:
         *
         *   1      __/\__
         *         /      \
         *        /\     / \
         *   2   54 52  53 /\
         *   3            55 51
         */

        for (script, length) in [("51", 3), ("52", 2), ("53", 2), ("54", 2), ("55", 3)].iter() {
            assert_eq!(
                *length,
                tree_info
                    .script_map
                    .get(&(ScriptBuf::from_hex(script).unwrap(), LeafVersion::TapScript))
                    .expect("Present Key")
                    .iter()
                    .next()
                    .expect("Present Path")
                    .0
                    .len()
            );
        }

        // Obtain the output key
        let output_key = tree_info.output_key();

        // Try to create and verify a control block from each path
        for (_weights, script) in script_weights {
            let ver_script = (script, LeafVersion::TapScript);
            let ctrl_block = tree_info.control_block(&ver_script).unwrap();
            assert!(ctrl_block.verify_taproot_commitment(
                &secp,
                output_key.to_inner(),
                &ver_script.0
            ))
        }
    }

    #[test]
    fn taptree_builder() {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str(
            "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        )
        .unwrap();

        let builder = TaprootBuilder::new();
        // Create a tree as shown below
        // For example, imagine this tree:
        // A, B , C are at depth 2 and D,E are at 3
        //                                       ....
        //                                     /      \
        //                                    /\      /\
        //                                   /  \    /  \
        //                                  A    B  C  / \
        //                                            D   E
        let a = ScriptBuf::from_hex("51").unwrap();
        let b = ScriptBuf::from_hex("52").unwrap();
        let c = ScriptBuf::from_hex("53").unwrap();
        let d = ScriptBuf::from_hex("54").unwrap();
        let e = ScriptBuf::from_hex("55").unwrap();
        let builder = builder.add_leaf(2, a.clone()).unwrap();
        let builder = builder.add_leaf(2, b.clone()).unwrap();
        let builder = builder.add_leaf(2, c.clone()).unwrap();
        let builder = builder.add_leaf(3, d.clone()).unwrap();

        // Trying to finalize an incomplete tree returns the Err(builder)
        let builder = builder.finalize(&secp, internal_key).unwrap_err();
        let builder = builder.add_leaf(3, e.clone()).unwrap();

        #[cfg(feature = "serde")]
        {
            let tree = TapTree::try_from(builder.clone()).unwrap();
            // test roundtrip serialization with serde_test
            #[rustfmt::skip]
            assert_tokens(&tree.readable(), &[
                Token::Seq { len: Some(10) },
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("51"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("52"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("55"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("54"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("53"), Token::U8(192), Token::TupleVariantEnd,
                Token::SeqEnd,
            ],);

            let node_info = TapTree::try_from(builder.clone()).unwrap().into_node_info();
            // test roundtrip serialization with serde_test
            #[rustfmt::skip]
            assert_tokens(&node_info.readable(), &[
                Token::Seq { len: Some(10) },
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("51"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("52"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("55"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("54"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("53"), Token::U8(192), Token::TupleVariantEnd,
                Token::SeqEnd,
            ],);
        }

        let tree_info = builder.finalize(&secp, internal_key).unwrap();
        let output_key = tree_info.output_key();

        for script in vec![a, b, c, d, e] {
            let ver_script = (script, LeafVersion::TapScript);
            let ctrl_block = tree_info.control_block(&ver_script).unwrap();
            assert!(ctrl_block.verify_taproot_commitment(
                &secp,
                output_key.to_inner(),
                &ver_script.0
            ))
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_leaf_version_serde() {
        let leaf_version = LeafVersion::TapScript;
        // use serde_test to test serialization and deserialization
        assert_tokens(&leaf_version, &[Token::U8(192)]);

        let json = serde_json::to_string(&leaf_version).unwrap();
        let leaf_version2 = serde_json::from_str(&json).unwrap();
        assert_eq!(leaf_version, leaf_version2);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_merkle_branch_serde() {
        let dummy_hash = hex!("03ba2a4dcd914fed29a1c630c7e811271b081a0e2f2f52cf1c197583dfd46c1b");
        let hash1 = TapNodeHash::from_slice(&dummy_hash).unwrap();
        let dummy_hash = hex!("8d79dedc2fa0b55167b5d28c61dbad9ce1191a433f3a1a6c8ee291631b2c94c9");
        let hash2 = TapNodeHash::from_slice(&dummy_hash).unwrap();
        let merkle_branch = TaprootMerkleBranch::from_collection(vec![hash1, hash2]).unwrap();
        // use serde_test to test serialization and deserialization
        serde_test::assert_tokens(
            &merkle_branch.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::Str("03ba2a4dcd914fed29a1c630c7e811271b081a0e2f2f52cf1c197583dfd46c1b"),
                Token::Str("8d79dedc2fa0b55167b5d28c61dbad9ce1191a433f3a1a6c8ee291631b2c94c9"),
                Token::SeqEnd,
            ],
        );
    }

    #[test]
    fn bip_341_tests() {
        fn process_script_trees(
            v: &serde_json::Value,
            mut builder: TaprootBuilder,
            leaves: &mut Vec<(ScriptBuf, LeafVersion)>,
            depth: u8,
        ) -> TaprootBuilder {
            if v.is_null() {
                // nothing to push
            } else if v.is_array() {
                for leaf in v.as_array().unwrap() {
                    builder = process_script_trees(leaf, builder, leaves, depth + 1);
                }
            } else {
                let script = ScriptBuf::from_hex(v["script"].as_str().unwrap()).unwrap();
                let ver =
                    LeafVersion::from_consensus(v["leafVersion"].as_u64().unwrap() as u8).unwrap();
                leaves.push((script.clone(), ver));
                builder = builder.add_leaf_with_ver(depth, script, ver).unwrap();
            }
            builder
        }

        let data = bip_341_read_json();
        // Check the version of data
        assert!(data["version"] == 1);
        let secp = &secp256k1::Secp256k1::verification_only();

        for arr in data["scriptPubKey"].as_array().unwrap() {
            let internal_key =
                XOnlyPublicKey::from_str(arr["given"]["internalPubkey"].as_str().unwrap()).unwrap();
            // process the tree
            let script_tree = &arr["given"]["scriptTree"];
            let mut merkle_root = None;
            if script_tree.is_null() {
                assert!(arr["intermediary"]["merkleRoot"].is_null());
            } else {
                merkle_root = Some(
                    TapNodeHash::from_str(arr["intermediary"]["merkleRoot"].as_str().unwrap())
                        .unwrap(),
                );
                let leaf_hashes = arr["intermediary"]["leafHashes"].as_array().unwrap();
                let ctrl_blks = arr["expected"]["scriptPathControlBlocks"].as_array().unwrap();
                let mut builder = TaprootBuilder::new();
                let mut leaves = vec![];
                builder = process_script_trees(script_tree, builder, &mut leaves, 0);
                let spend_info = builder.finalize(secp, internal_key).unwrap();
                for (i, script_ver) in leaves.iter().enumerate() {
                    let expected_leaf_hash = leaf_hashes[i].as_str().unwrap();
                    let expected_ctrl_blk = ControlBlock::decode(
                        &Vec::<u8>::from_hex(ctrl_blks[i].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();

                    let leaf_hash = TapLeafHash::from_script(&script_ver.0, script_ver.1);
                    let ctrl_blk = spend_info.control_block(script_ver).unwrap();
                    assert_eq!(leaf_hash.to_string(), expected_leaf_hash);
                    assert_eq!(ctrl_blk, expected_ctrl_blk);
                }
            }
            let expected_output_key =
                XOnlyPublicKey::from_str(arr["intermediary"]["tweakedPubkey"].as_str().unwrap())
                    .unwrap();
            let expected_tweak =
                TapTweakHash::from_str(arr["intermediary"]["tweak"].as_str().unwrap()).unwrap();
            let expected_spk =
                ScriptBuf::from_hex(arr["expected"]["scriptPubKey"].as_str().unwrap()).unwrap();
            let expected_addr =
                Address::from_str(arr["expected"]["bip350Address"].as_str().unwrap())
                    .unwrap()
                    .assume_checked();

            let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
            let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
            let addr = Address::p2tr(secp, internal_key, merkle_root, Network::Bitcoin);
            let spk = addr.script_pubkey();

            assert_eq!(expected_output_key, output_key.to_inner());
            assert_eq!(expected_tweak, tweak);
            assert_eq!(expected_addr, addr);
            assert_eq!(expected_spk, spk);
        }
    }

    fn bip_341_read_json() -> serde_json::Value {
        let json_str = include_str!("../tests/data/bip341_tests.json");
        serde_json::from_str(json_str).expect("JSON was not well-formatted")
    }
}
