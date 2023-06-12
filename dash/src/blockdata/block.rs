// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::fmt;

use hashes::{Hash, HashEngine};

use super::Weight;
use crate::blockdata::script;
use crate::blockdata::transaction::Transaction;
use crate::consensus::{encode, Decodable, Encodable};
use crate::error::Error::{self, BlockBadProofOfWork, BlockBadTarget};
pub use crate::hash_types::BlockHash;
use crate::hash_types::{TxMerkleNode, WitnessCommitment, WitnessMerkleNode, Wtxid};
use crate::internal_macros::impl_consensus_encoding;
use crate::pow::{CompactTarget, Target, Work};
use crate::prelude::*;
use crate::{io, merkle_tree, VarInt};

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] commiting to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce);

impl Header {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine).expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target { self.bits.into() }

    /// Computes the popular "difficulty" measure for mining.
    pub fn difficulty(&self) -> u128 { self.target().difficulty() }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 { self.target().difficulty_float() }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, Error> {
        let target = self.target();
        if target != required_target {
            return Err(BlockBadTarget);
        }
        let block_hash = self.block_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(BlockBadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work { self.target().to_work() }
}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// ### Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn from_consensus(v: i32) -> Self { Version(v) }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl Default for Version {
    fn default() -> Version { Self::NO_SOFT_FORK_SIGNALLING }
}

impl Encodable for Version {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coin_base() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase
            .output
            .iter()
            .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
        {
            let commitment = WitnessCommitment::from_slice(
                &coinbase.output[pos].script_pubkey.as_bytes()[6..38],
            )
            .unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment
                        == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(
        witness_root: &WitnessMerkleNode,
        witness_reserved_value: &[u8],
    ) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// base_size == size of header + size of encoded transaction count.
    fn base_size(&self) -> usize { 80 + VarInt(self.txdata.len() as u64).len() }

    /// Returns the size of the block.
    ///
    /// size == size of header + size of encoded transaction count + total size of transactions.
    pub fn size(&self) -> usize {
        let txs_size: usize = self.txdata.iter().map(Transaction::size).sum();
        self.base_size() + txs_size
    }

    /// Returns the strippedsize of the block.
    pub fn strippedsize(&self) -> usize {
        let txs_size: usize = self.txdata.iter().map(Transaction::strippedsize).sum();
        self.base_size() + txs_size
    }

    /// Returns the weight of the block.
    pub fn weight(&self) -> Weight {
        let base_weight = Weight::from_non_witness_data_size(self.base_size() as u64);
        let txs_weight: Weight = self.txdata.iter().map(Transaction::weight).sum();
        base_weight + txs_weight
    }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> { self.txdata.first() }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Bip34Error::Unsupported => write!(f, "block doesn't support BIP34"),
            Bip34Error::NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            Bip34Error::UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            Bip34Error::NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Bip34Error::*;

        match self {
            Unsupported | NotPresent | UnexpectedPush(_) | NegativeHeight => None,
        }
    }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash { header.block_hash() }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash { header.block_hash() }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash { block.block_hash() }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash { block.block_hash() }
}

#[cfg(test)]
mod tests {
    use hashes::hex::FromHex;

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::internal_macros::hex;

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().unwrap().txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 9-byte bip34 push
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d09a08601112233445566000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        let push = Vec::<u8>::from_hex("a08601112233445566").unwrap();
        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::UnexpectedPush(push)));
    }

    #[test]
    fn block_test() {
        // Mainnet block 0000000000000027facf8fffe7c4f92345edf06ee2615eae06b3e20392e22ddf

        let some_block = hex!("0000002085691f6a060e65346c281ed25b99dbd18c139053562ccd001d00000000000000377b6aa24658b7a0ae7b73f0673d047a291de5cbc06907038b288b2ebf491c2c99e17564c39d3219922665920403000500010000000000000000000000000000000000000000000000000000000000000000ffffffff330341ac1c0499e175642f706f6f6c696e2e636f6d2f5e9fea0288e95fd8864ea6cbf620d16e0c3c6af5d400f8e2030000000000ffffffff027eef8d08000000001976a9147fca51bce950b0ccf0a4994e3d6266202d27aa1f88ac59724506000000001976a914a8d608a131a5fd9c0ac063b33629da422adab17f88ac0000000046020041ac1c00facd1b5ccda08840168298c576b0c52223deb79340147fb85c71125b8bc9b1a1af27d4c4d5a7bfedec9d3fc55e518e69b6d19cb5e69e5e598390eb8e08d520ad020000000a3ad82d89650bd51c3c3a786b19dd96803486714806b23e2b2b80b0a2cc20940e0a0000006a473044022059522a9a08785941d94d49974defb8564df87b14c43e89012ab26a07a0e1fe3502206dd77ad419572dd313c10732c782c35af490ff4d7d66163251f8fb8e19e90673812103b305a67ea06e4e1f92348c3094e8f4f3ef4d2b71cfce820a3eb1146953aa54ecffffffff42053267bef6f60df91d82884d29e2958ef7f54841900a60ee6f05c60eace820090000006a47304402200590006238984ee825598c19fcdea59ab31dee2dbb070e5ccf0119944b4cb04902205fa8716d9bede943d541d17d4ca734db2d22ad3fed01c6c56c95054f155b69a58121039d44af4777fd248075efa405617ee359d154bad4f191a1891584a1bae2f0a3c8ffffffffab5326503d2a3aec5de7b6b103857014e2cbda352f6ce7f36ce5fab62d97ec5a060000006a47304402200877a392154cd6159a6cad5691c5a4966d9f82d2c6b1a9caee35cdcf483e10560220638fe365c0f06e99172095539a007bdd40d4fdd4e006b82de74b4ef2a8bc39bd8121036465d0697e496d4e8904af8bed6ddb62742d242ec590668e9f06cc6400c3bd48ffffffff0aa9307b3d4f088cd323a2d2d0eaeffd19c249a7f92ae515ac5bcc61d9d1636a090000006a473044022044e34eac2f10ffd13dba6f280cf652a6bbb7822f58e9d22b740de927f2c8f715022003ad63dd45e63fcd9bd3cbad50e263b47781e43ac826c5e9946ea85ac4112ccb812102537d0186300c6b3822c0a782fd759cde267578e1d6b91caa56f9f68742aa8cd2ffffffff793c4b443b64a24df23ca38a72868d2c47db3d59ac91e20ceecae49a0428a16e000000006a473044022047e3f22981b7ce4126833b1c30b9fcd26b94c7bb00685685eec459f9fef662cb022008261cfa827367ed6f435662f8e981aa151edd60732fe8e850d16775e59c9bc481210318dbab4b910f84ca2e39e8394ea1a8704e99ef63fec246828d11ea16890ae760ffffffff537dc28f8beb3e7e41fdf1b0334944fcee4d61fa2474544c3681e761899f5280010000006a47304402202d11266b3135fea8f306f9216fb0c2e616061fbd3123e6b2d5154f340c8b281202201b9979ed1e984e5897aa7588db9b6a5ab378ba8775b3bdd4cb1b22b35cc739328121021aaf09e74e7359025a081ad6287252fa548998a8eeb1f7b011e9b97076cc7a98ffffffffdb3822973be47001160dbde2cf4820935aaaf9ea44f57f8b74162caa40278e85020000006a47304402202e97c9e0648b079e674dab23e730ff8250b346f1bde1a4a9b5d6913593b0db9c0220502f8d462f44bab07f6ed4f38bfcf28e806b51a12b0b4b3d5ba44aabaa30cf71812103c217bda5f470049ac72891b3dc0713cc54eb47fa27cde0563a4e75231cb8d321ffffffffa5a31780a8882e415d9327c5eb92e0431eef0531b05fd9a0329b055818992f90070000006a4730440220016c79f9ba2e199e6c9c66600c451369934c277a21125f96f741158bd770ae3b0220497aca6bfcc27c9aa034b7a1d5e8701cb410cc19343ed97358aafd4a3a715c7981210231515594922ab111946501d73652075928fb8351e68f489281fd987b37dcacd1ffffffffa5a31780a8882e415d9327c5eb92e0431eef0531b05fd9a0329b055818992f900f0000006a47304402207d5f21240ac0e96401fcd76d505f09265ae495d5f16dd9a56a8f6f47e5bfd1d4022018ed8f4d809550ec56a89ae785374fb1d14ca31b4f1b064468ceed594d58fba581210205af51c307f2272edd6be30a40c9dee2264d695df18e8bf5085134b07c21aa90ffffffff0b0cc0f4193f5faf7989fec2d8113aae7fd4e0f02183d86f64a8e3ecfdb62ec6060000006a47304402204477e888b7add62c6f8e546cb022b3cfa66c8a3b47b19bc9da3977fa5e47719f02205c5f8dd019c40912675d461fb7e9df5659a116bc5d6bddf88105d744aedd5bf9812102a4d5640169a611d5a425cf283733bf1ca1e4305641e6e32f55318128996d49f6ffffffff0ae4969800000000001976a91402682b9c4057be3d659f8b77d816420eca6623a788ace4969800000000001976a914706e0929d67718f809f0d0cfc2a0dff33cd6211688ace4969800000000001976a91470bddf58d78cf86181bf8002e3814f5f9dcb6e9f88ace4969800000000001976a914939585a92055678e8e80f50c2fc95b18046309ed88ace4969800000000001976a914b2a4861161d70d3fea3711647039748307df371688ace4969800000000001976a914c68595efca8dcce63fc3f93fa4d50b959d13481088ace4969800000000001976a914cb7bf4a6f28c5fe4c61877a5b277cc4176362cd088ace4969800000000001976a914cbfc1fb5b084511d12b944e74be10128e6e2d8cd88ace4969800000000001976a914da5b67199ed49c897d8ebb8b9a4cb4b13389408f88ace4969800000000001976a914ff2928603068b6e604ff2f9068750055e8ac749888ac000000000200000010d56c3fb5729083036bbe413f2752f2ab953e676a8108ef1b9a02c5e88cff2e2b040000006a47304402201c0e70a104bb0e3d30fd2d1e48fb6bc7957e82f6dfe86d98fecdde4ce4e34dda0220250ade7d7728fa849f556714246af09a797b26d453025ab3b97cd5a97b511948812102a6b4e237a0819147f791f17fda43124f8b40f3096437223eb6528d7411eb4342ffffffff3626128fb20b46c9a5ca5996d3e17eb6b059cea8c4b658c773904aaa3f1ff249080000006a473044022033fb2bc10fcd57361c180891a76723420d8ca4b635ef8a99985ba95400d1e4cb02202895cf108b2c78c2cebaf93c028b3feb9779488e365917ca19fccca765c638b681210203bcf24fba0aa30424907f90af46810b504ae29c0a794e4aa623d2295f59ba02ffffffff81d261138ebb27392f6fa1a94bc1b167bbc4bf68226496f84f471def0688e15c000000006a4730440220698865708e1373d6dd1b9832feb7b1a9aef3bae91dcf28f961c5b3eae2b77b63022049e78aff60a6209784f5fcdb1f247628df705f341e8e02008a433d4a784e4d418121025da67e47364673678c414b4b1be6bf441e325d8b80ce1bb4bd9d0cec8d32b060ffffffff81d261138ebb27392f6fa1a94bc1b167bbc4bf68226496f84f471def0688e15c040000006a4730440220184e7db4f05b2492eb899d3356cb301978549fc5e2e2986d62d63b212d5d9f79022067df735167e9da604270123cfcc3823e8daf617eed31026f94cb6ae174ab439a812103d8d6d767e79a097a786a3605ce80abb825ffcc29c7f17a6e9ad7dd398f4335c3ffffffff814772ec42567b640407a372f586894901c568fd4fc73b5ce0db0221c3e29773020000006a47304402203eaf195a95c25766efb92f18f895fc70d73b90bb1d158494761ce88dc779194f02204151c2992f5db1825b74f8f890b34c379e3a2b7e25f239f2bb96232ed622270d812103e362c8e76402c4d3813acdde51d1f1cb19684a09b4b326a2ed953bac4fd9888effffffff814772ec42567b640407a372f586894901c568fd4fc73b5ce0db0221c3e29773040000006a473044022042d318b74f1031e2a5f576b5ed9d0462eecabb57e19f3f7e4a58e57dd762dc9e02200aaa477a98585deb96dd2315b005d497c79b758627ad110dbd7e5faf5dab867f812103070cf3ebe0c7b2e5fbdaa6be3944cbe8766d701d05238136fa437dc039b8ecc0ffffffff537a18df5db825ec6d9eaa00240980bf9fcd5ebf6a40c8f9d4be8393447797a8000000006a47304402205dd55ddd3b485cb01bcd2865c20978e1bfa3fecb8c039e0faa9140cc7d27798702206234729f192669e85c44f96747acd0addc96ed635f2b67baa8e985c60ebbbc0b812103c7cf68c84e37c979c80d742a2807b072c242182c01b4dea9bf8699848195d0f2ffffffff91e0d0a6dab204f8fd3cb0e08f38a4eb2f7e9a28994a9aecc82e0bcb846534ac030000006a47304402205b7e950e2e1f08b16c0c44699a15b62897a5341f91dbd0a380c3f48d708dcb2902203673e2b82a3c6b81fe6f16c76b30115b935e7d0ff202f12da2bdbfc33e2c9bcd812102f09850f520bdbbe99e00337acc64d7fc18302e462c86e6aa09ddd1b61cdddd28ffffffff41cd6d0c1b681c462ecd81d3a9c678c65cfe7b03395d33665de5fbe534d456bc050000006a473044022079fb358f35115270e00f8f8bac8f6b02c4aa378ea6fed0cbb2b0ac02c295b8f702203617a7b3b65874ae416157d456b47bbaaa9e25a52f9a0db78faa5300fb06c214812102bf7cbc7a053bf385bfa3ec688969b8651b08f8e94c784e58ef45ef70258313fdffffffff4d3eb5c68cab4b80e84ac5e3b51188cdedd8ceef1986b78c5490124379abd6d1030000006a4730440220449a56841e4464dc9e33d906638682da59d669b7db84ddbb305529ce71ca456c02203d8f5687ee7e84c7254604820c76153313c4585548186ac72ff55d19c05771628121025afdf790b0b230b317506b293330d41ca63ab83197f6e5b38d13b33a6a00b033ffffffff53a5f597eca73faeb7b4f7610335dca0c658deea93e253481f688ecfd96152e7000000006a47304402204d440844287bc727f3327ce1336258ac2781fbf82e30e9e784dd3298e6f66da3022027c5a2849b51c599fd4ab5ba4bef61c985f3367465f0eeb2f68326d1fd40f824812102d4863f469bfe817e9477e4042bb6f1713c12e10f5638def0e3bec634d8fd85acffffffff53a5f597eca73faeb7b4f7610335dca0c658deea93e253481f688ecfd96152e7010000006a4730440220743832b3b6686a1a8b9ca0448f4b83087d41e42af35b34f91e4f49b3053e00ad02206a530cd59ec90e9320aa5a82e3996d3cb44975d97dcf67aff9e8d6a8003290248121029acfd7260fc27e22c9f2022e7ec96696aecd6b7da016b3b2c91ae2521f4797cdffffffffff4c8668641d7c55da3ff999e82427a25f530506a3225c330b9f7c88c5ba66ef000000006a47304402201105740fc8c795ad181d8bdd55e35030311593748bada2e30be049ea024bd1ec022028dce0c5f9a57269df5c81f242788835473172e7e3a9b2c283732366c9afdc75812102f2966b931139ff638d2151259587ca599fcaf4c8f846ec5726194796680496ecffffffffd469e2c02a6778a27e1cfbe93a572b6a626656bb7003b41840c5866d580556f3050000006a47304402201e91be81d3cb2419888f9b36c9f76458754960d4708e36f00c08665807d57a8602204c9c9c24eedb64ecd3fb05efc33dddcd5fe452764fb3cd14c48a470141c3ec9681210399e0df6bd2ffe8c8ad539ff4bd4da3347b50668cd9faa2eb46a20388b7b056defffffffffdb9f6a1fa42912f780e2934c4ec62ae0286c9b70881e575b51edf15d7588ef9030000006a47304402205c4dd6255eae5837d6918e156b3a8ffd1c33b59de15ba6da6f3578b709241d5f0220503533b167dd964d02d3fc07e4cf9700c14c852b8c410d1b3efb37bee38cbe59812102f547c5df15d174e607ef6fc2c82915bbcb21216499a392f10adba9d1773da203ffffffffcb8ee0a132d041c36626f3e6c069581dace2d560fb909512fcb4b2e9c739d0f9020000006a473044022032f56ce481081e1c61f89c6c610b8792e9e76710030b73bed3e4415a0de73d7902202ac092ee5eea827adfe5e23b3173c14c2035c43d7307386a5d45bd6108a7e17a8121037cd08080ff21d1e2b93e46834ee3e97ea5cafde00ed9edd169d8c92c4083545affffffff10e8e4f505000000001976a9140046e46d2e7ce1c16311b18fdb000bda0a6f6f4b88ace8e4f505000000001976a9140c2b8b5135ff98b5818a4863ff1e07366ee7c6cd88ace8e4f505000000001976a914113c817b3892010ccc18e1d7a5cd41cdcb4b067488ace8e4f505000000001976a9141533f63fff866720a56bd7a9ddb1eede9951fd1a88ace8e4f505000000001976a914184c6d5eacf9bdb4d71ae46a7e0f948c91f8a21e88ace8e4f505000000001976a9141fc1243c8033dfa0da0a9446bbd581c485710d9188ace8e4f505000000001976a91421fe06d4a9b44b12b2936c01f8e7e11436877d5d88ace8e4f505000000001976a9142a21e4db869eb491058d50877d1caf6ee1776a4888ace8e4f505000000001976a91458e4a64c15f688bb5cfdf74f189ff0fa5764cf1088ace8e4f505000000001976a9147b444e78d84c8299e56b7ea9e396e5965cdc30ce88ace8e4f505000000001976a91482f6517250c73861b443c0a8a35083967f22db6f88ace8e4f505000000001976a914850be57051ccdf218596fb594607617ed2855bae88ace8e4f505000000001976a914c2100bdd46fdca6124a0ab98df490c0eb794ca3a88ace8e4f505000000001976a914cc789d163e7edf456fb5d667da324ee90da71b0088ace8e4f505000000001976a914dc9cd8fd452216e19000ca9c8ca66fd1d398611888ace8e4f505000000001976a914f44d542544fbfd1c142a7fd19895eea68353c05a88ac000000000200000001884e844b9834eee5c1ac5102ff36659ac00031b79e3469d8d51ce0ece03cdffb000000006a473044022072394a7fcf36a706f14af2e945c324ad0829bc0bd7bdcfdf168dc680340193bd02206544a84b36a4d9559833589ae61c0b5a9bfa98749afd56c0bafeb6f8accaaf2a0121027fefd9c8bfb835307de41de3ae81db6b8b424d5e14f24c33aff17efe8fd19437feffffff029e6f0000000000001976a914881abb65a9d47ea15865ae838400f6d0f96a941d88ac409c0000000000001976a91459fd86f4b9b0b6caefcadf80f6a0973efbfd9dbd88ac40ac1c00");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("85691f6a060e65346c281ed25b99dbd18c139053562ccd001d00000000000000");
        let merkle = hex!("377b6aa24658b7a0ae7b73f0673d047a291de5cbc06907038b288b2ebf491c2c");

        let work_bytes: [u8; 32] = hex!("000000000000000000000000000000000000000000000000050ec30af44bf25e").try_into().unwrap();
        let work = Work::from_be_bytes(work_bytes);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(536870912));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1685447065);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(422747587));
        assert_eq!(real_decode.header.nonce, 2456102546);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).
                unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 84852220);
        assert_eq!(real_decode.header.difficulty_float(), 84852220.19239795);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.size(), some_block.len());
        assert_eq!(real_decode.strippedsize(), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len() as u64)
        );

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[ignore]
    #[test]
    fn segwit_block_test() {
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = Work::from(0x257c3becdacc64_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(Version::USE_VERSION_BITS as i32)); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1472004949);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(0x1a06d450));
        assert_eq!(real_decode.header.nonce, 1879759182);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 2456598);
        assert_eq!(real_decode.header.difficulty_float(), 2456598.4399242126);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.size(), segwit_block.len());
        assert_eq!(real_decode.strippedsize(), 4283);
        assert_eq!(real_decode.weight(), Weight::from_wu(17168));

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));

        let block2 = hex!("000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, Version(-2147483648));
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("0000002085691f6a060e65346c281ed25b99dbd18c139053562ccd001d00000000000000377b6aa24658b7a0ae7b73f0673d047a291de5cbc06907038b288b2ebf491c2c99e17564c39d321992266592");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow(some_header.target()).unwrap(),
            some_header.block_hash()
        );

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(BlockBadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(BlockBadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");

        let header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");

        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1 << i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1 << 1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};
    use crate::EmptyWrite;

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
