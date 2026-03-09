# 0.1.0 - Initial migration

- Migrate all code from `rust-bitcoin::crypto::ecdsa` to this crate.
- Migrate all key types from `rust-bitcoin::crypto::key` to this crate. The `TapTweak` trait
  remains only in `rust-bitcoin`.
- Migrate sighash types and associated errors from `rust-bitcoin::crypto::sighash` to this crate.

# 0.0.0 - Initial dummy release

- Empty crate to reserve the name on crates.io
