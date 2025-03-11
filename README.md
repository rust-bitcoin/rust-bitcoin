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
    <a href="https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html"><img alt="Rustc Version 1.63.0+" src="https://img.shields.io/badge/rustc-1.63.0%2B-lightgrey.svg"/></a>
    <a href="https://gnusha.org/bitcoin-rust/"><img alt="Chat on IRC" src="https://img.shields.io/badge/irc-%23bitcoin--rust%20on%20libera.chat-blue"></a>
    <a href="https://github.com/model-checking/kani"><img alt="kani" src="https://github.com/rust-bitcoin/rust-bitcoin/workflows/Kani%20CI/badge.svg"></a>
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

It is recommended to always use [cargo-crev](https://github.com/crev-dev/cargo-crev) to verify the
trustworthiness of each of your dependencies, including this one.

## Known limitations

### Consensus

This library **must not** be used for consensus code (i.e. fully validating blockchain data). It
technically supports doing this, but doing so is very ill-advised because there are many deviations,
known and unknown, between this library and the Bitcoin Core reference implementation. In a
consensus based cryptocurrency such as Bitcoin it is critical that all parties are using the same
rules to validate data, and this library is simply unable to implement the same rules as Core.

Given the complexity of both C++ and Rust, it is unlikely that this will ever be fixed, and there
are no plans to do so. Of course, patches to fix specific consensus incompatibilities are welcome.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported, and we can't promise they will be. If you care about them
please let us know, so we can know how large the interest is and possibly decide to support them.

### Semver compliance

We try hard to maintain strict semver compliance with our releases. This codebase includes some
public functions marked unstable (e.g., `pub fn foo__unstable()`). These functions do not adhere to
semver rules; use them at your own discretion.


## Documentation

Currently can be found on [docs.rs/bitcoin](https://docs.rs/bitcoin/). Patches to add usage examples
and to expand on existing docs would be extremely appreciated.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please discuss them in an
issue before PRing them to avoid duplicate work and architectural mismatches. If you have any
questions or ideas you want to discuss please join us in
[#bitcoin-rust](https://web.libera.chat/?channel=#bitcoin-rust) on
[libera.chat](https://libera.chat).

For more information please see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.63.0**.

Use `Cargo-minimal.lock` to build the MSRV by copying to `Cargo.lock` and building.

## External dependencies

We integrate with a few external libraries, most notably `serde`. These
are available via feature flags. To ensure compatibility and MSRV stability we
provide two lock files as a means of inspecting compatible versions:
`Cargo-minimal.lock` containing minimal versions of dependencies and
`Cargo-recent.lock` containing recent versions of dependencies tested in our CI.

We do not provide any guarantees about the content of these lock files outside
of "our CI didn't fail with these versions". Specifically, we do not guarantee
that the committed hashes are free from malware. It is your responsibility to
review them.

## Installing Rust

Rust can be installed using your package manager of choice or [rustup.rs](https://rustup.rs). The
former way is considered more secure since it typically doesn't involve trust in the CA system. But
you should be aware that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-bitcoin` since we support much older versions than the
current stable one (see MSRV section).

## Building

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

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more
detailed instructions.

### No-std support

The `std` cargo feature is enabled by default. To build this project without the Rust standard
library, use the `--no-default-features` flag or set `default-features = false` in your dependency
declaration when adding it to your project.

For embedded device examples, see [`bitcoin/embedded`](https://github.com/rust-bitcoin/rust-bitcoin/tree/master/bitcoin/embedded)
or [`hashes/embedded`](https://github.com/rust-bitcoin/rust-bitcoin/tree/master/hashes/embedded).

### Just

We support [`just`](https://just.systems/man/en/) for running dev workflow commands. Run `just` from
your shell to see a list of available sub-commands.

### Building the docs

We build docs with the nightly toolchain, you may wish to use the following shell alias to check
your documentation changes build correctly.

```
alias build-docs='RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links'
```

## Testing

Unit and integration tests are available for those interested, along with benchmarks. For project
developers, especially new contributors looking for something to work on, we do:

- Fuzz testing with [`Honggfuzz`](https://github.com/rust-fuzz/honggfuzz-rs)
- Mutation testing with [`cargo-mutants`](https://github.com/sourcefrog/cargo-mutants)
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

We are doing mutation testing with [cargo-mutants](https://github.com/sourcefrog/cargo-mutants). To run
these tests first install with `cargo install --locked cargo-mutants` then run with `cargo mutants --in-place --no-shuffle`.
Note that running these mutation tests will take on the order of 10's of minutes.

### Code verification

We have started using [kani](https://github.com/model-checking/kani), install with `cargo install --locked kani-verifier`
 (no need to run `cargo kani setup`). Run the tests with `cargo kani`.

## Pull Requests

Every PR needs at least two reviews to get merged. During the review phase maintainers and
contributors are likely to leave comments and request changes. Please try to address them, otherwise
your PR might get closed without merging after a longer time of inactivity. If your PR isn't ready
for review yet please mark it by prefixing the title with `WIP: `.

### CI Pipeline

The CI pipeline requires approval before being run on each MR.

In order to speed up the review process the CI pipeline can be run locally using
[act](https://github.com/nektos/act). The `fuzz` and `Cross` jobs will be skipped when using `act`
due to caching being unsupported at this time. We do not *actively* support `act` but will merge PRs
fixing `act` issues.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. Copy the hooks in `githooks/`
to your githooks folder or run `just githooks-install` to copy them all.

## Policy on Altcoins/Altchains

Since the altcoin landscape includes projects which [frequently appear and disappear, and are poorly
designed anyway](https://download.wpsoftware.net/bitcoin/alts.pdf) we do not support any altcoins.
Supporting Bitcoin properly is already difficult enough and we do not want to increase the
maintenance burden and decrease API stability by adding support for other coins.

Our code is public domain so by all means fork it and go wild :)


## Release Notes

Release notes are done per crate, see:

- [`bitcoin` CHANGELOG](bitcoin/CHANGELOG.md)
- [`addresses` CHANGELOG](addresses/CHANGELOG.md)
- [`base58` CHANGELOG](base58/CHANGELOG.md)
- [`hashes` CHANGELOG](hashes/CHANGELOG.md)
- [`internals` CHANGELOG](internals/CHANGELOG.md)
- [`io` CHANGELOG](io/CHANGELOG.md)
- [`primitives` CHANGELOG](primitives/CHANGELOG.md)
- [`units` CHANGELOG](units/CHANGELOG.md)


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
