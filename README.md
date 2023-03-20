<div align="center">
  <h1>Rust Bitcoin</h1>

  <img alt="Rust Bitcoin logo by Hunter Trujillo, see license and source files under /logo" src="./logo/rust-bitcoin.png" width="300" />

  <p>Library with support for de/serialization, parsing and executing on data-structures
    and network messages related to Bitcoin.
  </p>

  <p>
    <a href="https://crates.io/crates/bitcoin"><img alt="Crate Info" src="https://img.shields.io/crates/v/bitcoin.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/actions?query=workflow%3AContinuous%20integration"><img alt="CI Status" src="https://github.com/rust-bitcoin/rust-bitcoin/workflows/Continuous%20integration/badge.svg"></a>
    <a href="https://docs.rs/bitcoin"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-bitcoin-green"/></a>
    <a href="https://blog.rust-lang.org/2020/02/27/Rust-1.41.1.html"><img alt="Rustc Version 1.41.1+" src="https://img.shields.io/badge/rustc-1.41.1%2B-lightgrey.svg"/></a>
    <a href="https://gnusha.org/bitcoin-rust/"><img alt="Chat on IRC" src="https://img.shields.io/badge/irc-%23bitcoin--rust%20on%20libera.chat-blue"></a>
    <a href="https://github.com/model-checking/kani"><imp alt="kani" src="https://github.com/rust-bitcoin/rust-bitcoin/actions/workflows/kani.yaml/badge.svg"></a>
    <img alt="Lines of code" src="https://img.shields.io/tokei/lines/github/rust-bitcoin/rust-bitcoin">
  </p>
</div>

[Documentation](https://docs.rs/bitcoin/)

Supports (or should support)

* De/serialization of Bitcoin protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP32 support)
* PSBT v0 de/serialization and all but the Input Finalizer role. Use [rust-miniscript](https://docs.rs/miniscript/latest/miniscript/psbt/index.html) to finalize.

For JSONRPC interaction with Bitcoin Core, it is recommended to use
[rust-bitcoincore-rpc](https://github.com/rust-bitcoin/rust-bitcoincore-rpc).

It is recommended to always use [cargo-crev](https://github.com/crev-dev/cargo-crev)
to verify the trustworthiness of each of your dependencies, including this one.

## Known limitations

### Consensus

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

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported and we can't promise they will be.
If you care about them please let us know, so we can know how large the interest
is and possibly decide to support them.

## Documentation

Currently can be found on [docs.rs/bitcoin](https://docs.rs/bitcoin/).
Patches to add usage examples and to expand on existing docs would be extremely
appreciated.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[#bitcoin-rust](https://web.libera.chat/?channel=#bitcoin-rust) on
[libera.chat](https://libera.chat).

For more information please see `./CONTRIBUTING.md`.

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features (minus
`no-std`) on **Rust 1.41.1** or **Rust 1.47** with `no-std`.

To build with the MSRV you will need to pin some dependencies (also for `no-std`):
```
cargo update -p serde --precise 1.0.156
cargo update -p syn --precise 1.0.107
```

## Installing Rust

Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-bitcoin` since we support much older
versions than the current stable one (see MSRV section).

## Building

The cargo feature `std` is enabled by default. At least one of the features `std` or `no-std` or both must be enabled.

Enabling the `no-std` feature does not disable `std`. To disable the `std` feature you must disable default features. The `no-std` feature only enables additional features required for this crate to be usable without `std`. Both can be enabled without conflict.

The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:rust-bitcoin/rust-bitcoin.git
cd rust-bitcoin
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more detailed instructions.

### Building the docs

We build docs with the nightly toolchain, you may wish to use the following
shell alias to check your documentation changes build correctly.

```
alias build-docs='RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links'
```

## Testing

Unit and integration tests are available for those interested, along with benchmarks. For project
developers, especially new contributors looking for something to work on, we do:

- Fuzz testing with [`Hongfuzz`](https://github.com/rust-fuzz/honggfuzz-rs)
- Mutation testing with [`Mutagen`](https://github.com/llogiq/mutagen)
- Code verification with [`Kani`](https://github.com/model-checking/kani)

There are always more tests to write and more bugs to find, contributions to our testing efforts
extremely welcomed. Please consider testing code a first class citizen, we definitely do take PRs
improving and cleaning up test code.

### Unit/Integration tests

Run as for any other Rust project `cargo test --all-features`.

### Benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench`.

### Mutation tests

We have started doing mutation testing with [mutagen](https://github.com/llogiq/mutagen). To run
these tests first install the latest dev version with `cargo +nightly install --git https://github.com/llogiq/mutagen`
then run with `RUSTFLAGS='--cfg=mutate' cargo +nightly mutagen`.

### Code verification

We have started using [kani](https://github.com/model-checking/kani), install with `cargo install
--locked kani-verifier` (no need to run `cargo kani setup`). Run the tests with `cargo kani`.

## Pull Requests

Every PR needs at least two reviews to get merged. During the review phase
maintainers and contributors are likely to leave comments and request changes.
Please try to address them, otherwise your PR might get closed without merging
after a longer time of inactivity. If your PR isn't ready for review yet please
mark it by prefixing the title with `WIP: `.

### CI Pipeline

The CI pipeline requires approval before being run on each MR.

In order to speed up the review process the CI pipeline can be run locally using
[act](https://github.com/nektos/act). The `fuzz` and `Cross` jobs will be
skipped when using `act` due to caching being unsupported at this time. We do
not *actively* support `act` but will merge PRs fixing `act` issues.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

## Policy on Altcoins/Altchains

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

See [CHANGELOG.md](CHANGELOG.md).


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE). We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX
IDs](https://spdx.dev/ids/).
