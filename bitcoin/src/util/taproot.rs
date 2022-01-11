// Rust Bitcoin Library
// Written in 2019 by
//     The rust-bitcoin developers.
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Bitcoin Taproot.
//!
//! This module provides support for taproot tagged hashes.
//!

use prelude::*;
use io;
use secp256k1::{self, Secp256k1};

use core::fmt;
use core::cmp::Reverse;
#[cfg(feature = "std")]
use std::error;

use hashes::{sha256, sha256t, Hash, HashEngine};
use schnorr::{TweakedPublicKey, UntweakedPublicKey, TapTweak};
use Script;

use consensus::Encodable;

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

/// The SHA-256 midstate value for the TapSigHash hash.
const MIDSTATE_TAPSIGHASH: [u8; 32] = [
    245, 4, 164, 37, 215, 248, 120, 59, 19, 99, 134, 138, 227, 229, 86, 88, 110, 238, 148, 93, 188,
    120, 136, 221, 2, 166, 226, 195, 24, 115, 254, 159,
];
// f504a425d7f8783b1363868ae3e556586eee945dbc7888dd02a6e2c31873fe9f

/// Internal macro to speficy the different taproot tagged hashes.
macro_rules! sha256t_hash_newtype {
    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr) => {
        sha256t_hash_newtype!($newtype, $tag, $midstate, $midstate_len, $docs, $reverse, stringify!($newtype));
    };

    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr, $sname:expr) => {
        #[doc = "The tag used for ["]
        #[doc = $sname]
        #[doc = "]"]
        #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        pub struct $tag;

        impl sha256t::Tag for $tag {
            fn engine() -> sha256::HashEngine {
                let midstate = sha256::Midstate::from_inner($midstate);
                sha256::HashEngine::from_midstate(midstate, $midstate_len)
            }
        }

        hash_newtype!($newtype, sha256t::Hash<$tag>, 32, $docs, $reverse);
    };
}

// Taproot test vectors from BIP-341 state the hashes without any reversing
sha256t_hash_newtype!(TapLeafHash, TapLeafTag, MIDSTATE_TAPLEAF, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree leafs", false
);
sha256t_hash_newtype!(TapBranchHash, TapBranchTag, MIDSTATE_TAPBRANCH, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree branches", false
);
sha256t_hash_newtype!(TapTweakHash, TapTweakTag, MIDSTATE_TAPTWEAK, 64,
    doc="Taproot-tagged hash for public key tweaks", false
);
sha256t_hash_newtype!(TapSighashHash, TapSighashTag, MIDSTATE_TAPSIGHASH, 64,
    doc="Taproot-tagged hash for the taproot signature hash", false
);

impl TapTweakHash {
    /// Create a new BIP341 [`TapTweakHash`] from key and tweak
    /// Produces H_taptweak(P||R) where P is internal key and R is the merkle root
    pub fn from_key_and_tweak(
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapBranchHash>,
    ) -> TapTweakHash {
        let mut eng = TapTweakHash::engine();
        // always hash the key
        eng.input(&internal_key.serialize());
        if let Some(h) = merkle_root {
            eng.input(&h);
        } else {
            // nothing to hash
        }
        TapTweakHash::from_engine(eng)
    }
}

impl TapLeafHash {
    /// function to compute leaf hash from components
    pub fn from_script(script: &Script, ver: LeafVersion) -> TapLeafHash {
        let mut eng = TapLeafHash::engine();
        ver.into_consensus()
            .consensus_encode(&mut eng)
            .expect("engines don't error");
        script
            .consensus_encode(&mut eng)
            .expect("engines don't error");
        TapLeafHash::from_engine(eng)
    }
}

/// Maximum depth of a Taproot Tree Script spend path
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L229
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// Size of a taproot control node
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L228
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// Tapleaf mask for getting the leaf version from first byte of control block
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L225
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// Tapscript leaf version
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L226
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Taproot annex prefix
pub const TAPROOT_ANNEX_PREFIX: u8 = 0x50;
/// Tapscript control base size
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L227
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// Tapscript control max size
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L230
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

// type alias for versioned tap script corresponding merkle proof
type ScriptMerkleProofMap = BTreeMap<(Script, LeafVersion), BTreeSet<TaprootMerkleBranch>>;

/// Data structure for representing Taproot spending information.
/// Taproot output corresponds to a combination of a
/// single public key condition (known the internal key), and zero or more
/// general conditions encoded in scripts organized in the form of a binary tree.
///
/// Taproot can be spent be either:
/// - Spending using the key path i.e., with secret key corresponding to the output_key
/// - By satisfying any of the scripts in the script spent path. Each script can be satisfied by providing
///   a witness stack consisting of the script's inputs, plus the script itself and the control block.
///
/// If one or more of the spending conditions consist of just a single key (after aggregation),
/// the most likely one should be made the internal key.
/// See [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) for more details
/// on choosing internal keys for a taproot application
///
/// Note: This library currently does not support [annex](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-5)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaprootSpendInfo {
    /// The BIP341 internal key.
    internal_key: UntweakedPublicKey,
    /// The Merkle root of the script tree (None if there are no scripts)
    merkle_root: Option<TapBranchHash>,
    /// The sign final output pubkey as per BIP 341
    output_key_parity: secp256k1::Parity,
    /// The tweaked output key
    output_key: TweakedPublicKey,
    /// Map from (script, leaf_version) to (sets of) [`TaprootMerkleBranch`].
    /// More than one control block for a given script is only possible if it
    /// appears in multiple branches of the tree. In all cases, keeping one should
    /// be enough for spending funds, but we keep all of the paths so that
    /// a full tree can be constructed again from spending data if required.
    script_map: ScriptMerkleProofMap,
}

impl TaprootSpendInfo {
    /// Create a new [`TaprootSpendInfo`] from a list of script(with default script version) and
    /// weights of satisfaction for that script. The weights represent the probability of
    /// each branch being taken. If probabilities/weights for each condition are known,
    /// constructing the tree as a Huffman tree is the optimal way to minimize average
    /// case satisfaction cost. This function takes input an iterator of tuple(u64, &Script)
    /// where usize represents the satisfaction weights of the branch.
    /// For example, [(3, S1), (2, S2), (5, S3)] would construct a TapTree that has optimal
    /// satisfaction weight when probability for S1 is 30%, S2 is 20% and S3 is 50%.
    ///
    /// # Errors:
    ///
    /// - When the optimal huffman tree has a depth more than 128
    /// - If the provided list of script weights is empty
    ///
    /// # Edge Cases:
    /// - If the script weight calculations overflow, a sub-optimal tree may be generated. This
    ///   should not happen unless you are dealing with billions of branches with weights close to
    ///   2^32.
    pub fn with_huffman_tree<C, I>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        script_weights: I,
    ) -> Result<Self, TaprootBuilderError>
    where
        I: IntoIterator<Item = (u32, Script)>,
        C: secp256k1::Verification,
    {
        let mut node_weights = BinaryHeap::<(Reverse<u64>, NodeInfo)>::new();
        for (p, leaf) in script_weights {
            node_weights.push((Reverse(p as u64), NodeInfo::new_leaf_with_ver(leaf, LeafVersion::TapScript)));
        }
        if node_weights.is_empty() {
            return Err(TaprootBuilderError::IncompleteTree);
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
        debug_assert!(node_weights.len() == 1);
        let node = node_weights.pop().expect("huffman tree algorithm is broken").1;
        return Ok(Self::from_node_info(secp, internal_key, node));
    }

    /// Create a new key spend with internal key and proided merkle root.
    /// Provide [`None`] for merkle_root if there is no script path.
    ///
    /// *Note*: As per BIP341
    ///
    /// When the merkle root is [`None`], the output key commits to an unspendable
    /// script path instead of having no script path. This is achieved by computing
    /// the output key point as Q = P + int(hashTapTweak(bytes(P)))G.
    /// See also [`TaprootSpendInfo::tap_tweak`].
    /// Refer to BIP 341 footnote (Why should the output key always have
    /// a taproot commitment, even if there is no script path?) for more details
    ///
    pub fn new_key_spend<C: secp256k1::Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapBranchHash>,
    ) -> Self {
        let (output_key, parity) = internal_key.tap_tweak(secp, merkle_root);
        Self {
            internal_key: internal_key,
            merkle_root: merkle_root,
            output_key_parity: parity,
            output_key: output_key,
            script_map: BTreeMap::new(),
        }
    }

    /// Obtain the tweak and parity used to compute the output_key
    pub fn tap_tweak(&self) -> TapTweakHash {
        TapTweakHash::from_key_and_tweak(self.internal_key, self.merkle_root)
    }

    /// Obtain the internal key
    pub fn internal_key(&self) -> UntweakedPublicKey {
        self.internal_key
    }

    /// Obtain the merkle root
    pub fn merkle_root(&self) -> Option<TapBranchHash> {
        self.merkle_root
    }

    /// Output key(the key used in script pubkey) from Spend data. See also
    /// [`TaprootSpendInfo::output_key_parity`]
    pub fn output_key(&self) -> TweakedPublicKey {
        self.output_key
    }

    /// Parity of the output key. See also [`TaprootSpendInfo::output_key`]
    pub fn output_key_parity(&self) -> secp256k1::Parity {
        self.output_key_parity
    }

    // Internal function to compute [`TaprootSpendInfo`] from NodeInfo
    fn from_node_info<C: secp256k1::Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        node: NodeInfo,
    ) -> TaprootSpendInfo {
        // Create as if it is a key spend path with the given merkle root
        let root_hash = Some(TapBranchHash::from_inner(node.hash.into_inner()));
        let mut info = TaprootSpendInfo::new_key_spend(secp, internal_key, root_hash);
        for leaves in node.leaves {
            let key = (leaves.script, leaves.ver);
            let value = leaves.merkle_branch;
            match info.script_map.get_mut(&key) {
                Some(set) => {
                    set.insert(value);
                    continue; // NLL fix
                }
                None => {}
            }
            let mut set = BTreeSet::new();
            set.insert(value);
            info.script_map.insert(key, set);
        }
        info
    }

    /// Access the internal script map
    pub fn as_script_map(&self) -> &ScriptMerkleProofMap {
        &self.script_map
    }

    /// Obtain a [`ControlBlock`] for particular script with the given version.
    /// Returns [`None`] if the script is not contained in the [`TaprootSpendInfo`]
    /// If there are multiple ControlBlocks possible, this returns the shortest one.
    pub fn control_block(&self, script_ver: &(Script, LeafVersion)) -> Option<ControlBlock> {
        let merkle_branch_set = self.script_map.get(script_ver)?;
        // Choose the smallest one amongst the multiple script maps
        let smallest = merkle_branch_set
            .iter()
            .min_by(|x, y| x.0.len().cmp(&y.0.len()))
            .expect("Invariant: Script map key must contain non-empty set value");
        Some(ControlBlock {
            internal_key: self.internal_key,
            output_key_parity: self.output_key_parity,
            leaf_version: script_ver.1,
            merkle_branch: smallest.clone(),
        })
    }
}

/// Builder for building taproot iteratively. Users can specify tap leaf or omitted/hidden
/// branches in a DFS(Depth first search) walk to construct this tree.
// Similar to Taproot Builder in bitcoin core
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaprootBuilder {
    // The following doc-comment is from bitcoin core, but modified for rust
    // The comment below describes the current state of the builder for a given tree.
    //
    // For each level in the tree, one NodeInfo object may be present. branch at index 0
    // is information about the root; further values are for deeper subtrees being
    // explored.
    //
    // During the construction of Taptree, for every right branch taken to
    // reach the position we're currently working in, there will be a (Some(_))
    // entry in branch corresponding to the left branch at that level.
    //
    // For example, imagine this tree:     - N0 -
    //                                    /      \
    //                                   N1      N2
    //                                  /  \    /  \
    //                                 A    B  C   N3
    //                                            /  \
    //                                           D    E
    //
    // Initially, branch is empty. After processing leaf A, it would become
    // {None, None, A}. When processing leaf B, an entry at level 2 already
    // exists, and it would thus be combined with it to produce a level 1 one,
    // resulting in {None, N1}. Adding C and D takes us to {None, N1, C}
    // and {None, N1, C, D} respectively. When E is processed, it is combined
    // with D, and then C, and then N1, to produce the root, resulting in {N0}.
    //
    // This structure allows processing with just O(log n) overhead if the leaves
    // are computed on the fly.
    //
    // As an invariant, there can never be None entries at the end. There can
    // also not be more than 128 entries (as that would mean more than 128 levels
    // in the tree). The depth of newly added entries will always be at least
    // equal to the current size of branch (otherwise it does not correspond
    // to a depth-first traversal of a tree). branch is only empty if no entries
    // have ever be processed. branch having length 1 corresponds to being done.
    //
    branch: Vec<Option<NodeInfo>>,
}

impl TaprootBuilder {
    /// Create a new instance of [`TaprootBuilder`]
    pub fn new() -> Self {
        TaprootBuilder { branch: vec![] }
    }
    /// Just like [`TaprootBuilder::add_leaf`] but allows to specify script version
    pub fn add_leaf_with_ver(
        self,
        depth: usize,
        script: Script,
        ver: LeafVersion,
    ) -> Result<Self, TaprootBuilderError> {
        let leaf = NodeInfo::new_leaf_with_ver(script, ver);
        self.insert(leaf, depth)
    }

    /// Add a leaf script at a depth `depth` to the builder with default script version.
    /// This will error if the leave are not provided in a DFS walk order. The depth of the
    /// root node is 0 and it's immediate child would be at depth 1.
    /// See [`TaprootBuilder::add_leaf_with_ver`] for adding a leaf with specific version
    /// See [Wikipedia](https://en.wikipedia.org/wiki/Depth-first_search) for more details
    pub fn add_leaf(self, depth: usize, script: Script) -> Result<Self, TaprootBuilderError> {
        self.add_leaf_with_ver(depth, script, LeafVersion::TapScript)
    }

    /// Add a hidden/omitted node at a depth `depth` to the builder.
    /// This will error if the node are not provided in a DFS walk order. The depth of the
    /// root node is 0 and it's immediate child would be at depth 1.
    pub fn add_hidden(self, depth: usize, hash: sha256::Hash) -> Result<Self, TaprootBuilderError> {
        let node = NodeInfo::new_hidden(hash);
        self.insert(node, depth)
    }

    /// Check if the builder is a complete tree
    pub fn is_complete(&self) -> bool {
        self.branch.len() == 1 && self.branch[0].is_some()
    }

    /// Create [`TaprootSpendInfo`] with the given internal key
    pub fn finalize<C: secp256k1::Verification>(
        mut self,
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
    ) -> Result<TaprootSpendInfo, TaprootBuilderError> {
        if self.branch.len() > 1 {
            return Err(TaprootBuilderError::IncompleteTree);
        }
        let node = self
            .branch
            .pop()
            .ok_or(TaprootBuilderError::EmptyTree)?
            .expect("Builder invariant: last element of the branch must be some");
        Ok(TaprootSpendInfo::from_node_info(secp, internal_key, node))
    }

    pub(crate) fn branch(&self) -> &[Option<NodeInfo>]{
        &self.branch
    }

    // Helper function to insert a leaf at a depth
    fn insert(mut self, mut node: NodeInfo, mut depth: usize) -> Result<Self, TaprootBuilderError> {
        // early error on invalid depth. Though this will be checked later
        // while constructing TaprootMerkelBranch
        if depth > TAPROOT_CONTROL_MAX_NODE_COUNT {
            return Err(TaprootBuilderError::InvalidMerkleTreeDepth(depth));
        }
        // We cannot insert a leaf at a lower depth while a deeper branch is unfinished. Doing
        // so would mean the add_leaf/add_hidden invocations do not correspond to a DFS traversal of a
        // binary tree.
        if depth + 1 < self.branch.len() {
            return Err(TaprootBuilderError::NodeNotInDfsOrder);
        }

        while self.branch.len() == depth + 1 {
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

        if self.branch.len() < depth + 1 {
            // add enough nodes so that we can insert node at depth `depth`
            let num_extra_nodes = depth + 1 - self.branch.len();
            self.branch
                .extend((0..num_extra_nodes).into_iter().map(|_| None));
        }
        // Push the last node to the branch
        self.branch[depth] = Some(node);
        Ok(self)
    }
}

// Internally used structure to represent the node information in taproot tree
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub(crate) struct NodeInfo {
    /// Merkle Hash for this node
    pub(crate) hash: sha256::Hash,
    /// information about leaves inside this node
    pub(crate) leaves: Vec<LeafInfo>,
}

impl NodeInfo {
    // Create a new NodeInfo with omitted/hidden info
    fn new_hidden(hash: sha256::Hash) -> Self {
        Self {
            hash: hash,
            leaves: vec![],
        }
    }

    // Create a new leaf with NodeInfo
    fn new_leaf_with_ver(script: Script, ver: LeafVersion) -> Self {
        let leaf = LeafInfo::new(script, ver);
        Self {
            hash: leaf.hash(),
            leaves: vec![leaf],
        }
    }

    // Combine two NodeInfo's to create a new parent
    fn combine(a: Self, b: Self) -> Result<Self, TaprootBuilderError> {
        let mut all_leaves = Vec::with_capacity(a.leaves.len() + b.leaves.len());
        for mut a_leaf in a.leaves {
            a_leaf.merkle_branch.push(b.hash)?; // add hashing partner
            all_leaves.push(a_leaf);
        }
        for mut b_leaf in b.leaves {
            b_leaf.merkle_branch.push(a.hash)?; // add hashing partner
            all_leaves.push(b_leaf);
        }
        let mut eng = TapBranchHash::engine();
        if a.hash < b.hash {
            eng.input(&a.hash);
            eng.input(&b.hash);
        } else {
            eng.input(&b.hash);
            eng.input(&a.hash);
        };
        Ok(Self {
            hash: sha256::Hash::from_engine(eng),
            leaves: all_leaves,
        })
    }
}

// Internally used structure to store information about taproot leaf node
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub(crate) struct LeafInfo {
    // The underlying script
    pub(crate) script: Script,
    // The leaf version
    pub(crate) ver: LeafVersion,
    // The merkle proof(hashing partners) to get this node
    pub(crate) merkle_branch: TaprootMerkleBranch,
}

impl LeafInfo {
    // Create an instance of Self from Script with default version and no merkle branch
    fn new(script: Script, ver: LeafVersion) -> Self {
        Self {
            script: script,
            ver: ver,
            merkle_branch: TaprootMerkleBranch(vec![]),
        }
    }

    // Compute a leaf hash for the given leaf
    fn hash(&self) -> sha256::Hash {
        let leaf_hash = TapLeafHash::from_script(&self.script, self.ver);
        sha256::Hash::from_inner(leaf_hash.into_inner())
    }
}

/// The Merkle proof for inclusion of a tree in a taptree hash
// The type of hash is sha256::Hash because the vector might contain
// both TapBranchHash and TapLeafHash
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaprootMerkleBranch(Vec<sha256::Hash>);

impl TaprootMerkleBranch {
    /// Obtain a reference to inner
    pub fn as_inner(&self) -> &[sha256::Hash] {
        &self.0
    }

    /// Create a merkle proof from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, TaprootError> {
        if sl.len() % TAPROOT_CONTROL_NODE_SIZE != 0 {
            Err(TaprootError::InvalidMerkleBranchSize(sl.len()))
        } else if sl.len() > TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(
                sl.len() / TAPROOT_CONTROL_NODE_SIZE,
            ))
        } else {
            let inner = sl
                // TODO: Use chunks_exact after MSRV changes to 1.31
                .chunks(TAPROOT_CONTROL_NODE_SIZE)
                .map(|chunk| {
                    sha256::Hash::from_slice(chunk)
                        .expect("chunk exact always returns the correct size")
                })
                .collect();
            Ok(TaprootMerkleBranch(inner))
        }
    }

    /// Serialize to a writer. Returns the number of bytes written
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        let mut written = 0;
        for hash in self.0.iter() {
            written += writer.write(hash)?;
        }
        Ok(written)
    }

    /// Serialize self as bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.0.iter().map(|e| e.as_inner()).flatten().map(|x| *x).collect::<Vec<u8>>()
    }

    // Internal function to append elements to proof
    fn push(&mut self, h: sha256::Hash) -> Result<(), TaprootBuilderError> {
        if self.0.len() >= TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootBuilderError::InvalidMerkleTreeDepth(self.0.len()))
        } else {
            self.0.push(h);
            Ok(())
        }
    }

    /// Create a MerkleProof from Vec<[`sha256::Hash`]>. Returns an error when
    /// inner proof len is more than TAPROOT_CONTROL_MAX_NODE_COUNT (128)
    pub fn from_inner(inner: Vec<sha256::Hash>) -> Result<Self, TaprootError> {
        if inner.len() > TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(inner.len()))
        } else {
            Ok(TaprootMerkleBranch(inner))
        }
    }

    /// Consume Self to get Vec<[`sha256::Hash`]>
    pub fn into_inner(self) -> Vec<sha256::Hash> {
        self.0
    }
}

/// Control Block data structure used in Tapscript satisfaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ControlBlock {
    /// The tapleaf version,
    pub leaf_version: LeafVersion,
    /// The parity of the output key (NOT THE INTERNAL KEY WHICH IS ALWAYS XONLY)
    pub output_key_parity: secp256k1::Parity,
    /// The internal key
    pub internal_key: UntweakedPublicKey,
    /// The merkle proof of a script associated with this leaf
    pub merkle_branch: TaprootMerkleBranch,
}

impl ControlBlock {
    /// Obtain a ControlBlock from slice. This is an extra witness element
    /// that provides the proof that taproot script pubkey is correctly computed
    /// with some specified leaf hash. This is the last element in
    /// taproot witness when spending a output via script path.
    ///
    /// # Errors:
    /// - If the control block size is not of the form 33 + 32m where
    /// 0 <= m <= 128, InvalidControlBlock is returned
    pub fn from_slice(sl: &[u8]) -> Result<ControlBlock, TaprootError> {
        if sl.len() < TAPROOT_CONTROL_BASE_SIZE
            || (sl.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(TaprootError::InvalidControlBlockSize(sl.len()));
        }
        let output_key_parity = secp256k1::Parity::from((sl[0] & 1) as i32);
        let leaf_version = LeafVersion::from_consensus(sl[0] & TAPROOT_LEAF_MASK)?;
        let internal_key = UntweakedPublicKey::from_slice(&sl[1..TAPROOT_CONTROL_BASE_SIZE])
            .map_err(TaprootError::InvalidInternalKey)?;
        let merkle_branch = TaprootMerkleBranch::from_slice(&sl[TAPROOT_CONTROL_BASE_SIZE..])?;
        Ok(ControlBlock {
            leaf_version,
            output_key_parity,
            internal_key,
            merkle_branch,
        })
    }

    /// Obtain the size of control block. Faster and more efficient than calling
    /// serialize() followed by len(). Can be handy for fee estimation
    pub fn size(&self) -> usize {
        TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.as_inner().len()
    }

    /// Serialize to a writer. Returns the number of bytes written
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        let first_byte: u8 = i32::from(self.output_key_parity) as u8 | self.leaf_version.into_consensus();
        let mut bytes_written = 0;
        bytes_written += writer.write(&[first_byte])?;
        bytes_written += writer.write(&self.internal_key.serialize())?;
        bytes_written += self.merkle_branch.encode(&mut writer)?;
        Ok(bytes_written)
    }

    /// Serialize the control block. This would be required when
    /// using ControlBlock as a witness element while spending an output via
    /// script path. This serialization does not include the VarInt prefix that would be
    /// applied when encoding this element as a witness.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.encode(&mut buf)
            .expect("writers don't error");
        buf
    }

    /// Verify that a control block is correct proof for a given output key and script
    /// This only checks that script is contained inside the taptree described by
    /// output key, full verification must also execute the script with witness data
    pub fn verify_taproot_commitment<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        output_key: &TweakedPublicKey,
        script: &Script,
    ) -> bool {
        // compute the script hash
        // Initially the curr_hash is the leaf hash
        let leaf_hash = TapLeafHash::from_script(&script, self.leaf_version);
        let mut curr_hash = TapBranchHash::from_inner(leaf_hash.into_inner());
        // Verify the proof
        for elem in self.merkle_branch.as_inner() {
            let mut eng = TapBranchHash::engine();
            if curr_hash.as_inner() < elem.as_inner() {
                eng.input(&curr_hash);
                eng.input(elem);
            } else {
                eng.input(elem);
                eng.input(&curr_hash);
            }
            // Recalculate the curr hash as parent hash
            curr_hash = TapBranchHash::from_engine(eng);
        }
        // compute the taptweak
        let tweak = TapTweakHash::from_key_and_tweak(self.internal_key, Some(curr_hash));
        self.internal_key.tweak_add_check(
            secp,
            output_key.as_inner(),
            self.output_key_parity,
            tweak.into_inner(),
        )
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
            TAPROOT_LEAF_TAPSCRIPT => unreachable!("FutureLeafVersion::from_consensus should be never called for 0xC0 value"),
            TAPROOT_ANNEX_PREFIX => Err(TaprootError::InvalidTaprootLeafVersion(TAPROOT_ANNEX_PREFIX)),
            odd if odd & 0xFE != odd => Err(TaprootError::InvalidTaprootLeafVersion(odd)),
            even => Ok(FutureLeafVersion(even))
        }
    }

    /// Get consensus representation of the future leaf version.
    #[inline]
    pub fn into_consensus(self) -> u8 {
        self.0
    }
}

impl fmt::Display for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

/// The leaf version for tapleafs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafVersion {
    /// BIP-342 tapscript
    TapScript,

    /// Future leaf version
    Future(FutureLeafVersion)
}

impl LeafVersion {
    /// Obtain LeafVersion from consensus byte representation.
    ///
    /// # Errors
    /// - If the last bit of the `version` is odd.
    /// - If the `version` is 0x50 ([`TAPROOT_ANNEX_PREFIX`]).
    // Text from BIP341:
    // In order to support some forms of static analysis that rely on
    // being able to identify script spends without access to the output being
    // spent, it is recommended to avoid using any leaf versions that would conflict
    // with a valid first byte of either a valid P2WPKH pubkey or a valid P2WSH script
    // (that is, both v and v | 1 should be an undefined, invalid or disabled opcode
    // or an opcode that is not valid as the first opcode).
    // The values that comply to this rule are the 32 even values between
    // 0xc0 and 0xfe and also 0x66, 0x7e, 0x80, 0x84, 0x96, 0x98, 0xba, 0xbc, 0xbe
    pub fn from_consensus(version: u8) -> Result<Self, TaprootError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => Ok(LeafVersion::TapScript),
            TAPROOT_ANNEX_PREFIX => Err(TaprootError::InvalidTaprootLeafVersion(TAPROOT_ANNEX_PREFIX)),
            future => FutureLeafVersion::from_consensus(future).map(LeafVersion::Future),
        }
    }

    /// Get consensus representation of the [`LeafVersion`].
    pub fn into_consensus(self) -> u8 {
        match self {
            LeafVersion::TapScript => TAPROOT_LEAF_TAPSCRIPT,
            LeafVersion::Future(version) => version.into_consensus(),
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
        fmt::LowerHex::fmt(&self.into_consensus(), f)
    }
}

impl fmt::UpperHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.into_consensus(), f)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for LeafVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
    {
        serializer.serialize_u8(self.into_consensus())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for LeafVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: ::serde::Deserializer<'de> {
        struct U8Visitor;
        impl<'de> ::serde::de::Visitor<'de> for U8Visitor {
            type Value = LeafVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid consensus-encoded taproot leaf version")
            }

            fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
            {
                LeafVersion::from_consensus(value).map_err(|_| {
                    E::invalid_value(::serde::de::Unexpected::Unsigned(value as u64), &"consensus-encoded leaf version as u8")
                })
            }
        }

        deserializer.deserialize_u8(U8Visitor)
    }
}

/// Detailed error type for taproot builder
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaprootBuilderError {
    /// Merkle Tree depth must not be more than 128
    InvalidMerkleTreeDepth(usize),
    /// Nodes must be added specified in DFS order
    NodeNotInDfsOrder,
    /// Two nodes at depth 0 are not allowed
    OverCompleteTree,
    /// Invalid taproot internal key
    InvalidInternalKey(secp256k1::Error),
    /// Called finalize on an incomplete tree
    IncompleteTree,
    /// Called finalize on a empty tree
    EmptyTree,
}

impl fmt::Display for TaprootBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaprootBuilderError::NodeNotInDfsOrder => {
                write!(f, "add_leaf/add_hidden must be called in DFS walk order",)
            }
            TaprootBuilderError::OverCompleteTree => write!(
                f,
                "Attempted to create a tree with two nodes at depth 0. There must\
                only be a exactly one node at depth 0",
            ),
            TaprootBuilderError::InvalidMerkleTreeDepth(d) => write!(
                f,
                "Merkle Tree depth({}) must be less than {}",
                d, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            TaprootBuilderError::InvalidInternalKey(e) => {
                write!(f, "Invalid Internal XOnly key : {}", e)
            }
            TaprootBuilderError::IncompleteTree => {
                write!(f, "Called finalize on an incomplete tree")
            }
            TaprootBuilderError::EmptyTree => {
                write!(f, "Called finalize on an empty tree")
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for TaprootBuilderError {}

/// Detailed error type for taproot utilities
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaprootError {
    /// Proof size must be a multiple of 32
    InvalidMerkleBranchSize(usize),
    /// Merkle Tree depth must not be more than 128
    InvalidMerkleTreeDepth(usize),
    /// The last bit of tapleaf version must be zero
    InvalidTaprootLeafVersion(u8),
    /// Invalid Control Block Size
    InvalidControlBlockSize(usize),
    /// Invalid taproot internal key
    InvalidInternalKey(secp256k1::Error),
    /// Empty TapTree
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
            TaprootError::InvalidTaprootLeafVersion(v) => write!(
                f,
                "Leaf version({}) must have the least significant bit 0",
                v
            ),
            TaprootError::InvalidControlBlockSize(sz) => write!(
                f,
                "Control Block size({}) must be of the form 33 + 32*m where  0 <= m <= {} ",
                sz, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            // TODO: add source when in MSRV
            TaprootError::InvalidInternalKey(e) => write!(f, "Invalid Internal XOnly key : {}", e),
            TaprootError::EmptyTree => write!(f, "Taproot Tree must contain at least one script"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for TaprootError {}
#[cfg(test)]
mod test {
    use {Address, Network};
    use schnorr::TapTweak;

    use super::*;
    use hashes::hex::{FromHex, ToHex};
    use hashes::sha256t::Tag;
    use hashes::{sha256, Hash, HashEngine};
    use secp256k1::{VerifyOnly, XOnlyPublicKey};
    use core::str::FromStr;
    extern crate serde_json;

    fn tag_engine(tag_name: &str) -> sha256::HashEngine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        engine
    }

    #[test]
    fn test_midstates() {
        // check midstate against hard-coded values
        assert_eq!(MIDSTATE_TAPLEAF, tag_engine("TapLeaf").midstate().into_inner());
        assert_eq!(MIDSTATE_TAPBRANCH, tag_engine("TapBranch").midstate().into_inner());
        assert_eq!(MIDSTATE_TAPTWEAK, tag_engine("TapTweak").midstate().into_inner());
        assert_eq!(MIDSTATE_TAPSIGHASH, tag_engine("TapSighash").midstate().into_inner());

        // test that engine creation roundtrips
        assert_eq!(tag_engine("TapLeaf").midstate(), TapLeafTag::engine().midstate());
        assert_eq!(tag_engine("TapBranch").midstate(), TapBranchTag::engine().midstate());
        assert_eq!(tag_engine("TapTweak").midstate(), TapTweakTag::engine().midstate());
        assert_eq!(tag_engine("TapSighash").midstate(), TapSighashTag::engine().midstate());

        // check that hash creation is the same as building into the same engine
        fn empty_hash(tag_name: &str) -> [u8; 32] {
            let mut e = tag_engine(tag_name);
            e.input(&[]);
            sha256::Hash::from_engine(e).into_inner()
        }
        assert_eq!(empty_hash("TapLeaf"), TapLeafHash::hash(&[]).into_inner());
        assert_eq!(empty_hash("TapBranch"), TapBranchHash::hash(&[]).into_inner());
        assert_eq!(empty_hash("TapTweak"), TapTweakHash::hash(&[]).into_inner());
        assert_eq!(empty_hash("TapSighash"), TapSighashHash::hash(&[]).into_inner());
    }

    #[test]
    fn test_vectors_core() {
        //! Test vectors taken from Core

        // uninitialized writers
        //   CHashWriter writer = HasherTapLeaf;
        //   writer.GetSHA256().GetHex()
        assert_eq!(
            TapLeafHash::from_engine(TapLeafTag::engine()).to_hex(),
            "5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb"
        );
        assert_eq!(
            TapBranchHash::from_engine(TapBranchTag::engine()).to_hex(),
            "53c373ec4d6f3c53c1f5fb2ff506dcefe1a0ed74874f93fa93c8214cbe9ffddf"
        );
        assert_eq!(
            TapTweakHash::from_engine(TapTweakTag::engine()).to_hex(),
            "8aa4229474ab0100b2d6f0687f031d1fc9d8eef92a042ad97d279bff456b15e4"
        );
        assert_eq!(
            TapSighashHash::from_engine(TapSighashTag::engine()).to_hex(),
            "dabc11914abcd8072900042a2681e52f8dba99ce82e224f97b5fdb7cd4b9c803"
        );

        // 0-byte
        //   CHashWriter writer = HasherTapLeaf;
        //   writer << std::vector<unsigned char>{};
        //   writer.GetSHA256().GetHex()
        // Note that Core writes the 0 length prefix when an empty vector is written.
        assert_eq!(
            TapLeafHash::hash(&[0]).to_hex(),
            "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829"
        );
        assert_eq!(
            TapBranchHash::hash(&[0]).to_hex(),
            "92534b1960c7e6245af7d5fda2588db04aa6d646abc2b588dab2b69e5645eb1d"
        );
        assert_eq!(
            TapTweakHash::hash(&[0]).to_hex(),
            "cd8737b5e6047fc3f16f03e8b9959e3440e1bdf6dd02f7bb899c352ad490ea1e"
        );
        assert_eq!(
            TapSighashHash::hash(&[0]).to_hex(),
            "c2fd0de003889a09c4afcf676656a0d8a1fb706313ff7d509afb00c323c010cd"
        );
    }

    fn _verify_tap_commitments(secp: &Secp256k1<VerifyOnly>, out_spk_hex: &str, script_hex : &str, control_block_hex: &str) {
        let out_pk = XOnlyPublicKey::from_str(&out_spk_hex[4..]).unwrap();
        let out_pk = TweakedPublicKey::dangerous_assume_tweaked(out_pk);
        let script = Script::from_hex(script_hex).unwrap();
        let control_block = ControlBlock::from_slice(&Vec::<u8>::from_hex(control_block_hex).unwrap()).unwrap();
        assert_eq!(control_block_hex, control_block.serialize().to_hex());
        assert!(control_block.verify_taproot_commitment(secp, &out_pk, &script));
    }

    #[test]
    fn control_block_verify() {
        let secp  = Secp256k1::verification_only();
        // test vectors obtained from printing values in feature_taproot.py from bitcoin core
        _verify_tap_commitments(&secp, "51205dc8e62b15e0ebdf44751676be35ba32eed2e84608b290d4061bbff136cd7ba9", "6a", "c1a9d6f66cd4b25004f526bfa873e56942f98e8e492bd79ed6532b966104817c2bda584e7d32612381cf88edc1c02e28a296e807c16ad22f591ee113946e48a71e0641e660d1e5392fb79d64838c2b84faf04b7f5f283c9d8bf83e39e177b64372a0cd22eeab7e093873e851e247714eff762d8a30be699ba4456cfe6491b282e193a071350ae099005a5950d74f73ba13077a57bc478007fb0e4d1099ce9cf3d4");
        _verify_tap_commitments(&secp, "5120e208c869c40d8827101c5ad3238018de0f3f5183d77a0c53d18ac28ddcbcd8ad", "f4", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40090ab1f4890d51115998242ebce636efb9ede1b516d9eb8952dc1068e0335306199aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4da14e029b1e154a85bfd9139e7aa2720b6070a4ceba8264ca61d5d3ac27aceb9ef4b54cd43c2d1fd5e11b5c2e93cf29b91ea3dc5b832201f02f7473a28c63246");
        _verify_tap_commitments(&secp, "5120567666e7df90e0450bb608e17c01ed3fbcfa5355a5f8273e34e583bfaa70ce09", "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ac", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400");
        _verify_tap_commitments(&secp, "5120580a19e47269414a55eb86d5d0c6c9b371455d9fd2154412a57dec840df99fe1", "6a", "bca0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40042ba1bd1c63c03ccff60d4c4d53a653f87909eb3358e7fa45c9d805231fb08c933e1f4e0f9d17f591df1419df7d5b7eb5f744f404c5ef9ecdb1b89b18cafa3a816d8b5dba3205f9a9c05f866d91f40d2793a7586d502cb42f46c7a11f66ad4aa");
        _verify_tap_commitments(&secp, "5120228b94a4806254a38d6efa8a134c28ebc89546209559dfe40b2b0493bafacc5b", "6a50", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4009c9aed3dfd11ab0e78bf87ef3bf296269dc4b0f7712140386d6980992bab4b45");
        _verify_tap_commitments(&secp, "5120567666e7df90e0450bb608e17c01ed3fbcfa5355a5f8273e34e583bfaa70ce09", "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ac", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400");
        _verify_tap_commitments(&secp, "5120b0a79103c31fe51eea61d2873bad8a25a310da319d7e7a85f825fa7a00ea3f85", "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ad51", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400");
        _verify_tap_commitments(&secp, "5120f2f62e854a0012aeba78cd4ba4a0832447a5262d4c6eb4f1c95c7914b536fc6c", "6a86", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4009ad3d30479f0689dbdf59a6b840d60ad485b2effbed1825a75ce19a44e460e09056f60ea686d79cfa4fb79f197b2e905ac857a983be4a5a41a4873e865aa950780c0237de279dc063e67deec46ef8e1bc351bf12c4d67a6d568001faf097e797e6ee620f53cfe0f8acaddf2063c39c3577853bb46d61ffcba5a024c3e1216837");
        _verify_tap_commitments(&secp, "51202a4772070b49bae68b44315032cdbf9c40c7c2f896781b32b931b73dbfb26d7e", "6af8", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4006f183944a14618fc7fe9ceade0f58e43a19d3c3b179ea6c43c29616413b6971c99aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4c3462adec78cd04f3cc156bdadec50def99feae0dc6a23664e8a2b0d42d6ca9eb968dfdf46c23af642b2688351904e0a0630e71ffac5bcaba33b9b2c8a7495ec");
        _verify_tap_commitments(&secp, "5120a32b0b8cfafe0f0f8d5870030ba4d19a8725ad345cb3c8420f86ac4e0dff6207", "4c", "e8a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400615da7ac8d078e5fc7f4690fc2127ba40f0f97cc070ade5b3a7919783d91ef3f13734aab908ae998e57848a01268fe8217d70bc3ee8ea8ceae158ae964a4b5f3af20b50d7019bf47fde210eee5c52f1cfe71cfca78f2d3e7c1fd828c80351525");
        _verify_tap_commitments(&secp, "5120b0a79103c31fe51eea61d2873bad8a25a310da319d7e7a85f825fa7a00ea3f85", "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ad51", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400");
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
        let internal_key = UntweakedPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();

        let script_weights = vec![
            (10, Script::from_hex("51").unwrap()), // semantics of script don't matter for this test
            (20, Script::from_hex("52").unwrap()),
            (20, Script::from_hex("53").unwrap()),
            (30, Script::from_hex("54").unwrap()),
            (19, Script::from_hex("55").unwrap()),
        ];
        let tree_info = TaprootSpendInfo::with_huffman_tree(&secp, internal_key, script_weights.clone()).unwrap();

        /* The resulting tree should put the scripts into a tree similar
         * to the following:
         *
         *   1      __/\__
         *         /      \
         *        /\     / \
         *   2   54 52  53 /\
         *   3            55 51
         */

        for (script, length) in vec![("51", 3), ("52", 2), ("53", 2), ("54", 2), ("55", 3)] {
            assert_eq!(
                length,
                tree_info
                    .script_map
                    .get(&(Script::from_hex(script).unwrap(), LeafVersion::TapScript))
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
            assert!(ctrl_block.verify_taproot_commitment(&secp, &output_key, &ver_script.0))
        }
    }

    #[test]
    fn taptree_builder() {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();

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
        let a = Script::from_hex("51").unwrap();
        let b = Script::from_hex("52").unwrap();
        let c = Script::from_hex("53").unwrap();
        let d = Script::from_hex("54").unwrap();
        let e = Script::from_hex("55").unwrap();
        let builder = builder.add_leaf(2, a.clone()).unwrap();
        let builder = builder.add_leaf(2, b.clone()).unwrap();
        let builder = builder.add_leaf(2, c.clone()).unwrap();
        let builder = builder.add_leaf(3, d.clone()).unwrap();
        let builder = builder.add_leaf(3, e.clone()).unwrap();

        let tree_info = builder.finalize(&secp, internal_key).unwrap();
        let output_key = tree_info.output_key();

        for script in vec![a, b, c, d, e] {
            let ver_script = (script, LeafVersion::TapScript);
            let ctrl_block = tree_info.control_block(&ver_script).unwrap();
            assert!(ctrl_block.verify_taproot_commitment(&secp, &output_key, &ver_script.0))
        }
    }

    #[test]
    fn bip_341_tests() {

        fn process_script_trees(
            v: &serde_json::Value,
            mut builder: TaprootBuilder,
            leaves: &mut Vec<(Script, LeafVersion)>,
            depth: usize,
        ) -> TaprootBuilder {
            if v.is_null() {
                // nothing to push
            } else if v.is_array() {
                for leaf in v.as_array().unwrap() {
                    builder =  process_script_trees(leaf, builder, leaves, depth + 1);
                }
            } else {
                let script = Script::from_str(v["script"].as_str().unwrap()).unwrap();
                let ver = LeafVersion::from_consensus(v["leafVersion"].as_u64().unwrap() as u8).unwrap();
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
            let internal_key = XOnlyPublicKey::from_str(arr["given"]["internalPubkey"].as_str().unwrap()).unwrap();
            // process the tree
            let script_tree = &arr["given"]["scriptTree"];
            let mut merkle_root = None;
            if script_tree.is_null() {
                assert!(arr["intermediary"]["merkleRoot"].is_null());
            } else {
                merkle_root = Some(TapBranchHash::from_str(&arr["intermediary"]["merkleRoot"].as_str().unwrap()).unwrap());
                let leaf_hashes = arr["intermediary"]["leafHashes"].as_array().unwrap();
                let ctrl_blks = arr["expected"]["scriptPathControlBlocks"].as_array().unwrap();
                let mut builder = TaprootBuilder::new();
                let mut leaves = vec![];
                builder = process_script_trees(&script_tree, builder, &mut leaves, 0);
                let spend_info = builder.finalize(secp, internal_key).unwrap();
                for (i, script_ver) in leaves.iter().enumerate() {
                    let expected_leaf_hash = leaf_hashes[i].as_str().unwrap();
                    let expected_ctrl_blk = ControlBlock::from_slice(&Vec::<u8>::from_hex(ctrl_blks[i].as_str().unwrap()).unwrap()).unwrap();

                    let leaf_hash = TapLeafHash::from_script(&script_ver.0, script_ver.1);
                    let ctrl_blk = spend_info.control_block(script_ver).unwrap();
                    assert_eq!(leaf_hash.to_hex(), expected_leaf_hash);
                    assert_eq!(ctrl_blk, expected_ctrl_blk);
                }
            }
            let expected_output_key = XOnlyPublicKey::from_str(arr["intermediary"]["tweakedPubkey"].as_str().unwrap()).unwrap();
            let expected_tweak = TapTweakHash::from_str(arr["intermediary"]["tweak"].as_str().unwrap()).unwrap();
            let expected_spk = Script::from_str(arr["expected"]["scriptPubKey"].as_str().unwrap()).unwrap();
            let expected_addr = Address::from_str(arr["expected"]["bip350Address"].as_str().unwrap()).unwrap();

            let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
            let (output_key, _parity) = internal_key.tap_tweak(&secp, merkle_root);
            let addr = Address::p2tr(&secp, internal_key, merkle_root, Network::Bitcoin);
            let spk = addr.script_pubkey();

            assert_eq!(expected_output_key, output_key.into_inner());
            assert_eq!(expected_tweak, tweak);
            assert_eq!(expected_addr, addr);
            assert_eq!(expected_spk, spk);
        }
    }

    fn bip_341_read_json() -> serde_json::Value {
        let json_str = include_str!("../../test_data/bip341_tests.json");
        serde_json::from_str(json_str).expect("JSON was not well-formatted")
    }
}
