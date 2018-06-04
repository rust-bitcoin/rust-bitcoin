[![Status](https://travis-ci.org/rust-bitcoin/rust-bitcoin.png?branch=master)](https://travis-ci.org/rust-bitcoin/rust-bitcoin)

# Rust Bitcoin Library

Library with support for de/serialization, parsing and executing on data
structures and network messages related to Bitcoin and other blockchain-based
currencies.

[Documentation](https://docs.rs/bitcoin/)

Supports (or should support)

* De/serialization of Bitcoin protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP32 support)
* Pay-to-contract support as in Appendix A of the [Blockstream sidechains whitepaper](https://www.blockstream.com/sidechains.pdf)

For JSONRPC interaction with Bitcoin Core, it is recommended to use [rust-jsonrpc](https://github.com/apoelstra/rust-jsonrpc)
which uses the underlying [strason library](https://github.com/apoelstra/strason)
which parses decimal numbers as strings, preventing precision errors.


# Known limitations

## Consensus

This library **must not** be used for consensus code (i.e. fully validating
blockchain data). It technically supports doing this, but doing so is very
ill-advised because there are many deviations, known and unknown, between
this library and the Bitcoin Core reference implementation. In a consensus
based cryptocurrency such as Bitcoin it is critical that all parties are
using the same rules to validate data, and this library is simply unable
to implement the same rules as Core.

Given the complexity of both C++ and Rust, it is unlikely that this will
ever be fixed, and there are no plans to do so. Of course, patches to
fix specific consensus incompatibilities are welcome.

## Documentation

Currently the [documentation](https://www.wpsoftware.net/rustdoc/bitcoin/)
is very sparse. Patches to add usage examples and to expand on existing
docs would be extremely appreciated.


# Policy on Altcoins/Altchains

Patches which add support for non-Bitcoin cryptocurrencies by adding constants
to existing enums (e.g. to set the network message magic-byte sequence) are
welcome. Anything more involved will be considered on a case-by-case basis,
as the altcoin landscape includes projects which [frequently appear and
disappear, and are poorly designed anyway](https://download.wpsoftware.net/bitcoin/alts.pdf)
and keeping the codebase maintainable is a large priority.

In general, things that improve cross-chain compatibility (e.g. support for
cross-chain atomic swaps) are more likely to be accepted than things which
support only a single blockchain.


## Release Notes

I will try to document all breaking changes here so that people upgrading will know
what they need to change.

### 0.11

Remove `num` dependency at Matt's request; agree this is obnoxious to require all
downstream users to also have a `num` dependency just so they can use `Uint256::from_u64`.

### 0.12

* The in-memory blockchain was moved into a dedicated project rust-bitcoin-chain.

* Removed old script interpreter

* A new optional feature "bitcoinconsenus" lets this library use Bitcoin Core's native
script verifier, wrappend into Rust by the rust-bitcoinconsenus project. 
See `Transaction::verify` and `Script::verify` methods.

* Replaced Base58 traits with `encode_slice`, `check_encode_slice`, from and `from_check` functions in the base58 module.

* Un-reversed the Debug output for Sha256dHash

* Add bech32 support

* Support segwit address types

### 0.13

* Move witnesses inside the `TxIn` structure

* Add `Transaction::get_weight()`

* Update bip143 `sighash_all` API to be more ergonomic

#### 0.13.1

* Add `Display` trait to uints, `FromStr` trait to `Network` enum

* Add witness inv types to inv enum, constants for Bitcoin regtest network, `is_coin_base` accessor for tx inputs

* Expose `merkleroot(Vec<Sha256dHash>)`

