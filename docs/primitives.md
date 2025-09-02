# primitives 1.0.0

Design considerations and TODOs for the `bitcoin-primitives 1.0.0` release.

## TODOs

### Remove `hashes` from the public API.

Required due to [C-STABLE](https://rust-lang.github.io/api-guidelines/necessities.html#c-stable).

Currently `hashes` shows up in the public API in all of our hash wrapper types. This can be seen by
grepping the API text files introduced in
[#4792](https://github.com/rust-bitcoin/rust-bitcoin/issues/4792) 

The wrapper types are:

```bash
$ grep hashes api/primitives/all-features.txt | grep impl | awk '{print $NF}'

bitcoin_primitives::block::BlockHash
bitcoin_primitives::block::WitnessCommitment
bitcoin_primitives::merkle_tree::TxMerkleNode
bitcoin_primitives::merkle_tree::WitnessMerkleNode
bitcoin_primitives::script::ScriptHash
bitcoin_primitives::script::WScriptHash
bitcoin_primitives::transaction::Ntxid
bitcoin_primitives::transaction::Txid
bitcoin_primitives::transaction::Wtxid
```

Using `Txid` as an example, `hashes` appears in the following places:

```bash
$ grep hashes api/primitives/all-features.txt | grep Txid

impl bitcoin_hashes::Hash for bitcoin_primitives::transaction::Txid
pub const fn bitcoin_primitives::transaction::Txid::as_byte_array(&self) -> &<bitcoin_hashes::sha256d::Hash as bitcoin_hashes::Hash>::Bytes
pub const fn bitcoin_primitives::transaction::Txid::from_byte_array(bytes: <bitcoin_hashes::sha256d::Hash as bitcoin_hashes::Hash>::Bytes) -> Self
pub const fn bitcoin_primitives::transaction::Txid::to_byte_array(self) -> <bitcoin_hashes::sha256d::Hash as bitcoin_hashes::Hash>::Bytes
pub type bitcoin_primitives::transaction::Txid::Bytes = <bitcoin_hashes::sha256d::Hash as bitcoin_hashes::Hash>::Bytes
```

All these come from the `hash_newtype` macro.

Usage of `hash_newtype` in `bitcoin` (i.e. other usage outside of `primitives`):

- `bip158::{FilterHash, FilterHeader}`
- `bip32::XKeyIdentifier`
- `crypto::key::{PubkeyHash, WPubkeyHash}`
- `crypto::sighash::{LegacySighash, SegwitV0Sighash}`
- `taproot::{TapLeafHash, TapNodeHash, TapTweakHash}`
