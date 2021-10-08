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

//! Taproot
//!
use prelude::*;
use io;
use secp256k1::{self, Secp256k1};

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use hashes::{sha256, sha256t, Hash, HashEngine};
use schnorr;
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

// Currently all taproot hashes are defined as being displayed backwards,
// but that can be specified individually per hash.
sha256t_hash_newtype!(TapLeafHash, TapLeafTag, MIDSTATE_TAPLEAF, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree leafs", true
);
sha256t_hash_newtype!(TapBranchHash, TapBranchTag, MIDSTATE_TAPBRANCH, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree branches", true
);
sha256t_hash_newtype!(TapTweakHash, TapTweakTag, MIDSTATE_TAPTWEAK, 64,
    doc="Taproot-tagged hash for public key tweaks", true
);
sha256t_hash_newtype!(TapSighashHash, TapSighashTag, MIDSTATE_TAPSIGHASH, 64,
    doc="Taproot-tagged hash for the taproot signature hash", true
);

impl TapTweakHash {

    /// Create a new BIP341 [`TapTweakHash`] from key and tweak
    /// Produces H_taptweak(P||R) where P is internal key and R is the merkle root
    pub fn from_key_and_tweak(
        internal_key: schnorr::PublicKey,
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
        ver.as_u8()
            .consensus_encode(&mut eng)
            .expect("engines don't err");
        script
            .consensus_encode(&mut eng)
            .expect("engines don't err");
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
    internal_key: schnorr::PublicKey,
    /// The Merkle root of the script tree (None if there are no scripts)
    merkle_root: Option<TapBranchHash>,
    /// The sign final output pubkey as per BIP 341
    output_key_parity: bool,
    /// The tweaked output key
    output_key: schnorr::PublicKey,
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
    /// - If the script weight calculations overflow. This should not happen unless you are
    /// dealing with numbers close to 2^64.
    pub fn with_huffman_tree<C, I>(
        secp: &Secp256k1<C>,
        internal_key: schnorr::PublicKey,
        script_weights: I,
    ) -> Result<Self, TaprootBuilderError>
    where
        I: IntoIterator<Item = (u64, Script)>,
        C: secp256k1::Verification,
    {
        let mut node_weights = BinaryHeap::<(u64, NodeInfo)>::new();
        for (p, leaf) in script_weights {
            node_weights.push((p, NodeInfo::new_leaf_with_ver(leaf, LeafVersion::default())));
        }
        if node_weights.is_empty() {
            return Err(TaprootBuilderError::IncompleteTree);
        }
        while node_weights.len() > 1 {
            // Combine the last two elements and insert a new node
            let (p1, s1) = node_weights.pop().expect("len must be at least two");
            let (p2, s2) = node_weights.pop().expect("len must be at least two");
            // Insert the sum of first two in the tree as a new node
            let p = p1.checked_add(p2).ok_or(TaprootBuilderError::ScriptWeightOverflow)?;
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
        internal_key: schnorr::PublicKey,
        merkle_root: Option<TapBranchHash>,
    ) -> Self {
        let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
        let mut output_key = internal_key;
        // # Panics:
        //
        // This would return Err if the merkle root hash is the negation of the secret
        // key corresponding to the internal key.
        // Because the tweak is derived as specified in BIP341 (hash output of a function),
        // this is unlikely to occur (1/2^128) in real life usage, it is safe to unwrap this
        let parity = output_key
            .tweak_add_assign(&secp, &tweak)
            .expect("TapTweakHash::from_key_and_tweak is broken");
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
    pub fn internal_key(&self) -> schnorr::PublicKey {
        self.internal_key
    }

    /// Obtain the merkle root
    pub fn merkle_root(&self) -> Option<TapBranchHash> {
        self.merkle_root
    }

    /// Output key(the key used in script pubkey) from Spend data. See also
    /// [`TaprootSpendInfo::output_key_parity`]
    pub fn output_key(&self) -> schnorr::PublicKey {
        self.output_key
    }

    /// Parity of the output key. See also [`TaprootSpendInfo::output_key`]
    pub fn output_key_parity(&self) -> bool {
        self.output_key_parity
    }

    // Internal function to compute [`TaprootSpendInfo`] from NodeInfo
    fn from_node_info<C: secp256k1::Verification>(
        secp: &Secp256k1<C>,
        internal_key: schnorr::PublicKey,
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
            leaf_version: LeafVersion::default(),
            merkle_branch: smallest.clone(),
        })
    }
}

/// Builder for building taproot iteratively. Users can specify tap leaf or omitted/hidden
/// branches in a DFS(Depth first search) walk to construct this tree.
// Similar to Taproot Builder in bitcoin core
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        self.add_leaf_with_ver(depth, script, LeafVersion::default())
    }

    /// Add a hidden/omitted node at a depth `depth` to the builder.
    /// This will error if the node are not provided in a DFS walk order. The depth of the
    /// root node is 0 and it's immediate child would be at depth 1.
    pub fn add_hidden(self, depth: usize, hash: sha256::Hash) -> Result<Self, TaprootBuilderError> {
        let node = NodeInfo::new_hidden(hash);
        self.insert(node, depth)
    }

    /// Create [`TaprootSpendInfo`] with the given internal key
    pub fn finalize<C: secp256k1::Verification>(
        mut self,
        secp: &Secp256k1<C>,
        internal_key: schnorr::PublicKey,
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
struct NodeInfo {
    /// Merkle Hash for this node
    hash: sha256::Hash,
    /// information about leaves inside this node
    leaves: Vec<LeafInfo>,
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
struct LeafInfo {
    // The underlying script
    script: Script,
    // The leaf version
    ver: LeafVersion,
    // The merkle proof(hashing partners) to get this node
    merkle_branch: TaprootMerkleBranch,
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
pub struct ControlBlock {
    /// The tapleaf version,
    pub leaf_version: LeafVersion,
    /// The parity of the output key (NOT THE INTERNAL KEY WHICH IS ALWAYS XONLY)
    pub output_key_parity: bool,
    /// The internal key
    pub internal_key: schnorr::PublicKey,
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
        let output_key_parity = (sl[0] & 1) == 1;
        let leaf_version = LeafVersion::from_u8(sl[0] & TAPROOT_LEAF_MASK)?;
        let internal_key = schnorr::PublicKey::from_slice(&sl[1..TAPROOT_CONTROL_BASE_SIZE])
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
        let first_byte: u8 =
            (if self.output_key_parity { 1 } else { 0 }) | self.leaf_version.as_u8();
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
        output_key: &schnorr::PublicKey,
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
            output_key,
            self.output_key_parity,
            tweak.into_inner(),
        )
    }
}

/// The leaf version for tapleafs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafVersion(u8);

impl Default for LeafVersion {
    fn default() -> Self {
        LeafVersion(TAPROOT_LEAF_TAPSCRIPT)
    }
}

impl LeafVersion {
    /// Obtain LeafVersion from u8, will error when last bit of ver is even or
    /// when ver is 0x50 (ANNEX_TAG)
    // Text from BIP341:
    // In order to support some forms of static analysis that rely on
    // being able to identify script spends without access to the output being
    // spent, it is recommended to avoid using any leaf versions that would conflict
    // with a valid first byte of either a valid P2WPKH pubkey or a valid P2WSH script
    // (that is, both v and v | 1 should be an undefined, invalid or disabled opcode
    // or an opcode that is not valid as the first opcode).
    // The values that comply to this rule are the 32 even values between
    // 0xc0 and 0xfe and also 0x66, 0x7e, 0x80, 0x84, 0x96, 0x98, 0xba, 0xbc, 0xbe
    pub fn from_u8(ver: u8) -> Result<Self, TaprootError> {
        if ver & TAPROOT_LEAF_MASK == ver && ver != 0x50 {
            Ok(LeafVersion(ver))
        } else {
            Err(TaprootError::InvalidTaprootLeafVersion(ver))
        }
    }

    /// Get the inner version from LeafVersion
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

impl Into<u8> for LeafVersion {
    fn into(self) -> u8 {
        self.0
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
    /// Script weight overflow
    ScriptWeightOverflow,
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
            TaprootBuilderError::ScriptWeightOverflow => {
                write!(f, "Script weight overflow in Huffman tree construction")
            },
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
    use super::*;
    use hashes::hex::ToHex;
    use hashes::sha256t::Tag;
    use hashes::{sha256, Hash, HashEngine};

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
            "cbfa0621df37662ca57697e5847b6abaf92934a1a5624916f8d177a388c21252"
        );
        assert_eq!(
            TapBranchHash::from_engine(TapBranchTag::engine()).to_hex(),
            "dffd9fbe4c21c893fa934f8774eda0e1efdc06f52ffbf5c1533c6f4dec73c353"
        );
        assert_eq!(
            TapTweakHash::from_engine(TapTweakTag::engine()).to_hex(),
            "e4156b45ff9b277dd92a042af9eed8c91f1d037f68f0d6b20001ab749422a48a"
        );
        assert_eq!(
            TapSighashHash::from_engine(TapSighashTag::engine()).to_hex(),
            "03c8b9d47cdb5f7bf924e282ce99ba8d2fe581262a04002907d8bc4a9111bcda"
        );

        // 0-byte
        //   CHashWriter writer = HasherTapLeaf;
        //   writer << std::vector<unsigned char>{};
        //   writer.GetSHA256().GetHex()
        // Note that Core writes the 0 length prefix when an empty vector is written.
        assert_eq!(
            TapLeafHash::hash(&[0]).to_hex(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
        assert_eq!(
            TapBranchHash::hash(&[0]).to_hex(),
            "1deb45569eb6b2da88b5c2ab46d6a64ab08d58a2fdd5f75a24e6c760194b5392"
        );
        assert_eq!(
            TapTweakHash::hash(&[0]).to_hex(),
            "1eea90d42a359c89bbf702ddf6bde140349e95b9e8036ff1c37f04e6b53787cd"
        );
        assert_eq!(
            TapSighashHash::hash(&[0]).to_hex(),
            "cd10c023c300fb9a507dff136370fba1d8a0566667cfafc4099a8803e00dfdc2"
        );
    }
}
