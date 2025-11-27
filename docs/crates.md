# rust-bitcoin stack of crates

The `rust-bitcoin` project is in the, very long, process of crate
smashing. The original single `rust-bitcoin` crate has already been
broken into a number of pieces and this work is ongoing. Both current
and future crates are documented here. Future crates typically have an
entry in [roadmap.md] and likely also a file of their own.

## Current crates

- `addresses`: **Empty** placeholder (see future crates below).
- `base58`: Bitcoin base58 encoding and decoding (for pre-segwit addresses).
- `bitcoin`: The `rust-bitcoin` crate.
- `chacha20_poly1305`: ChaCha20 stream cipher with the Poly1305 MAC.
- `consensus_encoding`: Consensus encoding and decoding.
- `crypto`: Cryptography support for the rust-bitcoin ecosystem.
- `hashes`: Rust Bitcoin hashes library.
- `internals`: Used internally by crates in this repo.
- `io`: Rust Bitcoin I/O library (to support `no_std`).
- `p2p`: Rust Bitcoin peer to peer message types.
- `primitives`: Rust Bitcoin primitive types.
- `units`: Rust Bitcoin unit types.

### Crates in our stack but in different repositories

A few crates are in different repositories, primarily because they were either started by different
people or they have a (slightly) different set of maintainers and/or merge policy.

- `secp256k1`: https://github.com/rust-bitcoin/rust-secp256k1
- `bech32`: https://github.com/rust-bitcoin/rust-bech32
- `hex-conservative`: https://github.com/rust-bitcoin/hex-conservative
- `miniscript`: https://github.com/rust-bitcoin/rust-miniscript

## Future crates

- `addresses`: Bitcoin addresses (see [addresses.md])
- `bip-32`: BIP-0032 (and maybe BIP-0380) support (see [bip-32.md])
- `psbt`: PSBTv2 support (see [psbt.md])
- `keys`/`crypto`: Cryptography stuff or maybe just keys (see [keys.md])

## Re-export policy

See `./policy.md`.

[addresses.md]: ./addresses.md
[bip-32.md]: ./bip-32.md
[keys.md]: ./keys.md
[psbt.md]: ./psbt.md
