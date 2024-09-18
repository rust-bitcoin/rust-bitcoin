# 0.101.0 - 2024-09-18

Move the following modules and types from `rust-bitcoin` to `bitcoin-primitives`:

- `locktime`: `absolute::LockTime`, `relative::LockTime`
- `opcodes`: `Opcode`
- `pow`: `CompactTarget`
- `sequence`: `Sequence`
- `transaction`: `Txid`, `Wtxid`, `Version`

# 0.100.0 - 2024-07-01

* Initial release of the `github.com/rust-bitcoin/rust-bitcoin/primitives` crate as
  `bitcoin-primitives`. The name on crates.io was generously transferred to us.
