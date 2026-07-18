# Changelog

## [Unreleased]

# [0.103.0] - 2026-07-14

- Move `script_hash` and `wscript_hash` to primitives [#6504](https://github.com/rust-bitcoin/rust-bitcoin/pull/6504)
- Move `builder` script functions to primitives [#6514](https://github.com/rust-bitcoin/rust-bitcoin/pull/6514)
- script: make `new_p2wsh` available on hashable scripts [#6498](https://github.com/rust-bitcoin/rust-bitcoin/pull/6498)
- hashes: Introduce `drain_to_hash` and `encode_to_hash` [#6456](https://github.com/rust-bitcoin/rust-bitcoin/pull/6456)
- Implement `ExactSizeEncoder` for `WitnessEncoder` [#6428](https://github.com/rust-bitcoin/rust-bitcoin/pull/6428)
- Adjust `Arbitrary` impls to enforce invariants from decoders [#6407](https://github.com/rust-bitcoin/rust-bitcoin/pull/6407)
- Seal the `Tag` trait [#6403](https://github.com/rust-bitcoin/rust-bitcoin/pull/6403)
- Move `serde_as_consensus` to `consensus_encoding` [#6395](https://github.com/rust-bitcoin/rust-bitcoin/pull/6395)
- Move some script functions to `primitives` [#6342](https://github.com/rust-bitcoin/rust-bitcoin/pull/6342)
- Replace `HexPrimitive` decoding with `consensus_encoding` [#6330](https://github.com/rust-bitcoin/rust-bitcoin/pull/6330)
- Move `Builder` to `primitives` [#6313](https://github.com/rust-bitcoin/rust-bitcoin/pull/6313)
- Move `WitnessVersion` to `primitives` [#6307](https://github.com/rust-bitcoin/rust-bitcoin/pull/6307)
- Move `Opcode` to `primitives` [#6306](https://github.com/rust-bitcoin/rust-bitcoin/pull/6306)
- Simplify and optimize witness decoder [#6321](https://github.com/rust-bitcoin/rust-bitcoin/pull/6321)
- Remove double allocation from `ScriptBuf::from_hex_prefixed` [#6295](https://github.com/rust-bitcoin/rust-bitcoin/pull/6295)
- Implement `fmt::LowerHex` and `fmt::UpperHex` for `Witness` [#6316](https://github.com/rust-bitcoin/rust-bitcoin/pull/6316)
- Avoid allocating claimed size when decoding witness length [#6298](https://github.com/rust-bitcoin/rust-bitcoin/pull/6298)
- Fix witness commitment check (BIP-141) [#6250](https://github.com/rust-bitcoin/rust-bitcoin/pull/6250)
- witness: Allocate in `reserve_batch` if `capacity < MIN_VECTOR_ALLOCATE` [#6241](https://github.com/rust-bitcoin/rust-bitcoin/pull/6241)
- Use optimized `sha256d` for 64-byte in merkle root computation [#5946](https://github.com/rust-bitcoin/rust-bitcoin/pull/5946)
- Move `PushBytes` and co to `primitives` [#6128](https://github.com/rust-bitcoin/rust-bitcoin/pull/6128)
- Remove the unstable `hex-conservative` dependency [#6148](https://github.com/rust-bitcoin/rust-bitcoin/pull/6148)
- Add minimum allocation size [#6198](https://github.com/rust-bitcoin/rust-bitcoin/pull/6198)
- witness: Allocate in `reserve_batch` if `capacity < MIN_VECTOR_ALLOCATE` [#6241](https://github.com/rust-bitcoin/rust-bitcoin/pull/6241)
- Add `SignetBlockScript`/`Buf` for signet challenge scripts [#5871](https://github.com/rust-bitcoin/rust-bitcoin/pull/5871)
- Move script hex parsing functions to `primitives` [#5657](https://github.com/rust-bitcoin/rust-bitcoin/pull/5657)
- Remove `From<SubError>` for error types [#5855](https://github.com/rust-bitcoin/rust-bitcoin/pull/5855)
- Do not re-export non-essential hash types [#5891](https://github.com/rust-bitcoin/rust-bitcoin/pull/5891)
- Re-export `serde` and `arbitrary` when they appear in public API [#5862](https://github.com/rust-bitcoin/rust-bitcoin/pull/5862)
- Implement stringly traits for `Block` using hex [#5703](https://github.com/rust-bitcoin/rust-bitcoin/pull/5703)
- Move `TxMerkleNodeDecoder`/`Error` to `merkle_tree` module [#5724](https://github.com/rust-bitcoin/rust-bitcoin/pull/5724)
- Remove excess allocations from `Witness::from_iter` [#5650](https://github.com/rust-bitcoin/rust-bitcoin/pull/5650)
- Remove `BlockTime` decoder from root export [#5527](https://github.com/rust-bitcoin/rust-bitcoin/pull/5527)
- Upgrade to `bitcoin-units 0.5.0` [#6292](https://github.com/rust-bitcoin/rust-bitcoin/pull/6292)
- Upgrade to `bitcoin_hashes 1.0.0`
- Upgrade to `consensus-encoding 1.0.0`

## [0.102.0] - 2026-02-17

It was found that the `1.0.0-rc.x` releases were troublesome because
of how `cargo` resolves version numbers that include a suffix. For
this reason we elected to go back to pre-1.0 version numbers but this
release is still explicitly a 1.0 release candidate.

- Remove `From<UnexpectedEof>` for primitive decoder error types [#5606](https://github.com/rust-bitcoin/rust-bitcoin/pull/5606)
- Use `hashes` format implementations and fix reverse hashes [#5603](https://github.com/rust-bitcoin/rust-bitcoin/pull/5603)
- Add fmt traits for simple wrapper types [#5597](https://github.com/rust-bitcoin/rust-bitcoin/pull/5597)
- Use saturating add in `WitnessDecoder` [#5569](https://github.com/rust-bitcoin/rust-bitcoin/pull/5569)
- Reject transactions with 0 outputs [#5470](https://github.com/rust-bitcoin/rust-bitcoin/pull/5470)
- Prevent null prevout in non-coinbase transactions [#5450](https://github.com/rust-bitcoin/rust-bitcoin/pull/5450)
- Reject txs with output sum > MAX_MONEY [#5443](https://github.com/rust-bitcoin/rust-bitcoin/pull/5443)
- Reject transactions with invalid coinbase `scriptSig` length [#5430](https://github.com/rust-bitcoin/rust-bitcoin/pull/5430)

## 1.0.0 Release Candidates - 2025-10-18

This changelog is a rolling description of everything that will eventually end up in `v1.0`.
EDIT: This changelog is for `1.0.0-rc.0` through `1.0.0-rc.2` and may well be missing stuff.

There are a bunch of changes in this stable release, of note script
tagging and the consensus encoding re-write.

- Introduce script tagging [#4907](https://github.com/rust-bitcoin/rust-bitcoin/pull/4907)
- Introduce pull encoding and use it for blockhash computation [#4912](https://github.com/rust-bitcoin/rust-bitcoin/pull/4912)
- Implement `Encodable` for `&Script<T>` [#4978](https://github.com/rust-bitcoin/rust-bitcoin/pull/4978)

And also we did:

- Remove `hashes` from the public API [#4935](https://github.com/rust-bitcoin/rust-bitcoin/pull/4935)
- Bump MSRV from 1.63.0 to 1.74.0 for all crates in the repo [#4926](https://github.com/rust-bitcoin/rust-bitcoin/pull/4926)
- Rename `units::parse` to `parse_int` [#4886](https://github.com/rust-bitcoin/rust-bitcoin/pull/4886)
- Introduce `Ntxid` [#4839](https://github.com/rust-bitcoin/rust-bitcoin/pull/4839)
- Remove `serde` impls from some primitive types [#4806](https://github.com/rust-bitcoin/rust-bitcoin/pull/48064806)
- Pluralize transaction fields [#4788](https://github.com/rust-bitcoin/rust-bitcoin/pull/4788)
- Use `CompactSize` instead of `VarInt` [#4790](https://github.com/rust-bitcoin/rust-bitcoin/pull/4790)
- Do not derive `Default` on `CompactTarget` [#4561](https://github.com/rust-bitcoin/rust-bitcoin/pull/4561)
- Deserialize witness from a list of hex strings [#4366](https://github.com/rust-bitcoin/rust-bitcoin/pull/4366)
- Implement `FromIterator` for `Witness` [#4365](https://github.com/rust-bitcoin/rust-bitcoin/pull/4365)
- Return `ControlBlock` from `Witness::taproot_control_block` [#4281](https://github.com/rust-bitcoin/rust-bitcoin/pull/4281)
- Witness api improvements and test cleanups [#4279](https://github.com/rust-bitcoin/rust-bitcoin/pull/4279)
- Implement `Display` for `Header` [#4269](https://github.com/rust-bitcoin/rust-bitcoin/pull/4269)
- Make `hex` optional [#4262](https://github.com/rust-bitcoin/rust-bitcoin/pull/4262)
- Clean up Witness API [#4186](https://github.com/rust-bitcoin/rust-bitcoin/pull/4186)
- Move `taproot` back to `bitcoin` crate [#4129](https://github.com/rust-bitcoin/rust-bitcoin/pull/4129)
- Make `transaction::Version` field private [#4099](https://github.com/rust-bitcoin/rust-bitcoin/pull/4099)
- Hide error internals [#4091](https://github.com/rust-bitcoin/rust-bitcoin/pull/4091)
- locktimes: Remove `PartialOrd` and `ArbitraryOrd` [#4065](https://github.com/rust-bitcoin/rust-bitcoin/pull/4065)
- Make `Debug` representation of `Witness` to be slice of hex-encoded
  bytes strings to improve readability [#4061](https://github.com/rust-bitcoin/rust-bitcoin/pull/4061)
- Implement `Default` for `Script` [#4043](https://github.com/rust-bitcoin/rust-bitcoin/pull/4043)
- Store `transaction::Version` as `u32` instead of `i32` [#4040](https://github.com/rust-bitcoin/rust-bitcoin/pull/4040)
- Delete `TxOut::NULL` [#3978](https://github.com/rust-bitcoin/rust-bitcoin/pull/3978)
- Reduce alloc requirements [#3711](https://github.com/rust-bitcoin/rust-bitcoin/pull/3711)
- Remove `serde` from amounts [#3672](https://github.com/rust-bitcoin/rust-bitcoin/pull/3672)
- Fix bug in witness stack getters [#3601](https://github.com/rust-bitcoin/rust-bitcoin/pull/3601)
- Re-design and move `Block` to `primitives` [#3582](https://github.com/rust-bitcoin/rust-bitcoin/pull/3582)
- Re-export `block::Header` as `BlockHeader` [#3562](https://github.com/rust-bitcoin/rust-bitcoin/pull/3562)
- Favour `to_vec` over `to_bytes` [#3544](https://github.com/rust-bitcoin/rust-bitcoin/pull/3544)

### Locktimes

Lock times got a bit of work. A big win was:

- Improve lock times - fix off-by-one bug #4468

There was a bit of churn so we are not listing all the PRs. Better
just to take a look at the new and improved API.

If you persist locktimes using `serde` you may want to look at because
we changed the format:

- Modify locktime serde implementations #4511

### Arbitrary

- Add Arbitrary impl for BlockHash, TxMerkleNode, and Wtxid #4720
- Add Arbitrary impl for relative::LockTime #4689

### Mutation testing

The whole crate is mutation tested using `cargo-mutants` - BOOM!

## [0.101.0] - 2024-11-15

This is the first "real" release of the `primitives` crate, as such it
includes a lot of work. Search GitHub with the following filter to see
all related PRs: `is:pr label:C-primitives merged:<=2024-11-15`

Move the following modules and types from `rust-bitcoin` to `bitcoin-primitives`:

- `block`: `Block`, `Header`, `Version`, `BlockHash`, `WitnessCommitment`, `Validation`, `Checked`, `Unchecked`
- `locktime`: `absolute::LockTime`, `relative::LockTime`
- `merkle_tree`: `TxMerkleNode`, `WitnessMerkleNode`
- `opcodes`: `Opcode`
- `pow`: `CompactTarget`
- `sequence`: `Sequence`
- `taproot`: `TapBranchTag`, `TapLeafHash`, `TapLeafTag`, `TapNodeHash`, `TapTweakHash`, `TapTweakTag`
- `transaction`: `Transaction`, `TxIn`, `TxOut`, `OutPoint`, `Txid`, `Wtxid`, `Version`
- `witness`: `Witness`, `Iter`

And various error types. See re-exports at the crate root and also in `rust-bitcoin` at the crate
root and from the respective module.

We hope to very soon release `primitives 1.0` - please raise any and all issues you come across no
matter how small so we can fix them for the stable release.

Enjoy!

## 0.100.0 - 2024-07-01

* Initial release of the `github.com/rust-bitcoin/rust-bitcoin/primitives` crate as
  `bitcoin-primitives`. The name on crates.io was generously transferred to us.

[Unreleased]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-primitives-0.103.0...HEAD
[0.103.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/primitives-0.102.0...bitcoin-primitives-0.103.0
[0.102.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/primitives-0.101.0...bitcoin-primitives-0.102.0
[0.101.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/primitives-0.100.0...primitives-0.101.0
