# Bitcoin Hashes Library

This is a simple, no-dependency library which implements the hash functions
needed by Bitcoin. These are SHA1, SHA256, SHA256d, SHA512, and RIPEMD160. As an
ancilliary thing, it exposes hexadecimal serialization and deserialization,
since these are needed to display hashes anway.

[Documentation](https://docs.rs/bitcoin_hashes/)

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.48.0**.


To build with the MSRV you will need to pin `serde` (if you have either the `serde` or the
`schemars` feature enabled)

```
# serde 1.0.157 uses syn 2.0 which requires edition 2021
cargo update -p serde --precise 1.0.156
```

before building. (And if your code is a library, your downstream users will need to run these
commands, and so on.)

## Contributions

Contributions are welcome, including additional hash function implementations.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

### Running Benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench`.
