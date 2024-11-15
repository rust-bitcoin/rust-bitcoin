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
