# 1.0.0 - 2025-10-18

This changelog is a rolling description of everything that will eventually end up in `v1.0`.

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

## Locktimes

Lock times got a bit of work. A big win was:

- Improve lock times - fix off-by-one bug #4468

There was a bit of churn so we are not listing all the PRs. Better
just to take a look at the new and improved API.

If you persist locktimes using `serde` you may want to look at because
we changed the format:

- Modify locktime serde implementations #4511

## Arbitrary

- Add Arbitrary impl for BlockHash, TxMerkleNode, and Wtxid #4720
- Add Arbitrary impl for relative::LockTime #4689

## Mutation testing

The whole crate is mutation tested using `cargo-mutants` - BOOM!

# 0.101.0 - 2024-11-15

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

# 0.100.0 - 2024-07-01

* Initial release of the `github.com/rust-bitcoin/rust-bitcoin/primitives` crate as
  `bitcoin-primitives`. The name on crates.io was generously transferred to us.
