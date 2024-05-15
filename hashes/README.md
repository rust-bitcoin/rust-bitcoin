# Bitcoin Hashes Library

This is a simple, minimal-dependency library which implements the hash functions needed by Bitcoin.
As an ancillary thing, it exposes hexadecimal serialization and deserialization, since these are
needed to display hashes anyway.

Currently we support:

- `RIPEMD` (specifically `RIPEMD-160`)
- `SHA-1`
- `SHA-2`
  - `SHA-256`
  - `SHA-384`
  - `SHA-512`
  - `SHA-512_256`
- `SipHash` (specifically `SipHash-2-4`)
- `SHA-256t` (tagged `SHA-256`)
- `SHA-256d` (double `SHA-256`)
- `HASH-160` (`SHA-256` then `RIPEMD-160`)
- `HMAC-X`, where `X` is any of the hashes above.

[Documentation](https://docs.rs/bitcoin_hashes/)

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.56.1**.

## Contributions

Contributions are welcome, including additional hash function implementations.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:

```bash
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

### Running Benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench`.
