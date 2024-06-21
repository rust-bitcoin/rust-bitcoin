# HOWTO

## Create the `primitives` crate

### Move/copy files

- Edit `primitives/src/lib.rs`

- `mv bitcoin/src/blockdata/* primitives/src`


- `mv bitcoin/src/consensus primitives/src`
- `mv bitcoin/src/crypto primitives/src`
- `mv bitcoin/src/merkle_tree primitives/src`
- `mv bitcoin/src/taproot primitives/src`
- `mv bitcoin/src/policy.rs primitives/src`
- `mv bitcoin/src/pow.rs primitives/src`
- `mv bitcoin/src/network.rs primitives/src`
- `cp bitcoin/src/serde_utils.rs primitives/src`
- `cp bitcoin/src/test_macros.rs primitives/src`
- Create `primitives/src/internal_macros.rs` by copying macros from `bitcoin`

### Make it build

- Copy the test from `mod.rs` (from `blockdata/` move) to `test.rs` and delete `mod.rs`
- Create `key.rs` by moving hash types out of `crypto/key.rs`
- Replace `rand-std` feature gating with `crypto-std`
- Feature gate secp256k1 stuff with `#[cfg(feature = "crypto")]`
- Fix all the paths (remove blockdata etc.)
- Add `consensus::GenericEncodeVec` trait (ie the trigger)
- Fix the path in all calls to `include_str!` (by adding bitcoin eg `../../bitcoin/tests`)
