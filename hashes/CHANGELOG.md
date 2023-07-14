# 0.13.0 - 2023-06-29

The main improvement in this version is removal of the `hex` module in favour of the new
[`hex-conservative`](https://crates.io/crates/hex-conservative) crate (which we wrote). We also
bumped the Minimum Supported Rust Version across the `rust-bitcoin` ecosystem to v1.48

* Bump MSRV to 1.48.0 [#1729](https://github.com/rust-bitcoin/rust-bitcoin/pull/1729).
* Depend on new `hex-conservative` crate and remove `hex` module [#1883](https://github.com/rust-bitcoin/rust-bitcoin/pull/1833).
* Convert enum `crate::Error` to struct `crate::FromSliceError`.
* Make `sha256t_hash_newtype!` evocative of the output [#1773](https://github.com/rust-bitcoin/rust-bitcoin/pull/1773).
* Implement computing SHA256 in const context [#1769](https://github.com/rust-bitcoin/rust-bitcoin/pull/1769).
* Add `from_bytes_ref` and `from_bytes_mut` to all hash types [#1761](https://github.com/rust-bitcoin/rust-bitcoin/pull/1761).
* Rename `crate::Error` to `crate::FromSliceError` [#1873](https://github.com/rust-bitcoin/rust-bitcoin/pull/1873).
* Add simd sha256 intrinsics for x86 machines [#1962](https://github.com/rust-bitcoin/rust-bitcoin/pull/1962).
* Introduce the "small-hash" feature for `bitcoin_hashes` [#1990](https://github.com/rust-bitcoin/rust-bitcoin/pull/1990).

# 0.12.0 - 2023-03-05

0.12 is a significant release. We pulled the repository into the rust-bitcoin
repo to improve our integration testing and to get more eyes on this crate. We
began the process of replacing the hex functionality in this crate with a more
performant, dedicated crate, and otherwise cleaning up the API as we look forward
to 1.0.

* [Remove `FromHex` implementation](https://github.com/rust-bitcoin/rust-bitcoin/pull/1565/commits/a308e1e2ea5c6ae419d961b8da71cc8a35a92715)
from all hashes and implement `FromStr` instead.
* Move crate from [original repo](https://github.com/rust-bitcoin/bitcoin_hashes) to the
`rust-bitcoin` repository. Commit history was lost during move, for commit history see the original
repository. Tip of bitcoin_hashes:master at time of import: 54c16249e06cc6b7870c7fc07d90f489d82647c7
* [Remove `Deref` impls for all hashes](https://github.com/rust-bitcoin/rust-bitcoin/pull/1450)
* [Add `AsRef` impls for all hashes from fixed-size arrays](https://github.com/rust-bitcoin/rust-bitcoin/pull/1593)
* [Add the `sha512_256` hash](https://github.com/rust-bitcoin/rust-bitcoin/pull/1413)
* [Remove the `ToHex` trait in favor of `DisplayHex` and `fmt::Display`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1531)
* [Remove the now-unused `HexWriter` object](https://github.com/rust-bitcoin/rust-bitcoin/pull/1572)
* [nostd: `alloc` feature no longer enables `core2`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1612)
* [Rewrite `hash_newtype` macro with new syntax](https://github.com/rust-bitcoin/rust-bitcoin/pull/1659)
* [Rename `Hash::Inner` to `Hash::Bytes`, 'Hash::*_inner` and several related conversion methods](https://github.com/rust-bitcoin/rust-bitcoin/pull/1577)


# 0.11.0 - 2022-06-25

The major change in this version is the increase of the Minimum Supported Rust Version (MSRV) from
1.29 to 1.41.1. This is a big change because it introduces Rust Edition 2018 to the codebase along
with all the benefits that brings. We also did a bunch of optimisations to speed up encoding and
decoding hex strings.

## Breaking changes

* [Enable edition 2018 and bump MSRV to Rust 1.41.1](https://github.com/rust-bitcoin/bitcoin_hashes/pull/136)

## New features/APIs

* [Add `all_zeros` to `Hash` trait](https://github.com/rust-bitcoin/bitcoin_hashes/pull/148)
* [Implement `Write` on `HmacEngine`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/133)
* [Introduce `HexWriter`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/156), makes serialising hex faster
* [Implement `Read` on `HexIterator`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/135), makes deserialising hex faster

## Other improvements

* Use `rotate_left` [instead of custom macro](https://github.com/rust-bitcoin/bitcoin_hashes/pull/162)
* [Enable clippy on CI](https://github.com/rust-bitcoin/bitcoin_hashes/pull/152)
* Various docs fixes
* [Improve feature test coverage](https://github.com/rust-bitcoin/bitcoin_hashes/pull/147)
* [Add a disabled `rustfmt.toml`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/141) to improve interaction with auto-formatting in editors


# 0.10.0 - 2021-07-05

* Increase `core2` to released version of 0.3.0

# 0.9.7 - 2021-06-17

* Introduce `alloc` feature and `core2` dependency for nostd support (this feature has MSRV of 1.36 rather than 1.29)

# 0.9.6 - 2021-05-03

* Re-export `core` as `_export::_core`. This resolves an issue when calling several exported macros with the `std` feature.

# 0.9.5 - 2021-04-28

* Add [`#[repr(transparent)]` to all newtype wrappers](https://github.com/rust-bitcoin/bitcoin_hashes/pull/108/)
* Add [missing `#derive`s](https://github.com/rust-bitcoin/bitcoin_hashes/pull/110/)
* Replace `fuzztarget` feature with [use of `cfg(fuzzing)`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/111/)
* Use [`core` rather than `std`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/118/) and [fix `no_std` compilation](https://github.com/rust-bitcoin/bitcoin_hashes/pull/122/)

Note that we have stopped re-exporting the `core` crate when compiling without `std`. This is technically a breaking change but it is hard to imagine what user might be affected.

# 0.9.4 - 2020-10-23

* Add `Hmac::from_inner_engines`

# 0.9.3 - 2020-10-19

* More serde macro fixes

# 0.9.2 - 2020-10-18

* Fix rustc 1.29.0 downstream issues with serde macros

# 0.9.2 - 2020-10-16

* Fix visibility issue with serde macros

# 0.9.1 - 2020-10-07

* Add `FromStr` impl to `sha256t::Hash`
* Fix `Hash::engine()` implementation for hash newtypes
* Add `sha256t_hash_newtype!` macro for creating tagged hashes

# 0.9.0 - 2020-08-27

* **Update MSRV to 1.29.0**

# 0.8.0 - 2020-08-26

* Add `as_inner` method to `Hash` trait
* Add `n_bytes_hashed` to `HashEngine` trait

# 0.7.6 - 2020-04-05

* Support hash newtypes with reversed hex serialization.

# 0.7.5 - 2020-04-02

* Add `sha256t` module for SHA-256-based tagged hashes.
* Add `FromStr` for hash newtypes.
* Add `from_hash` for hash newtypes.

# 0.7.3 - 2019-12-18

* Add `as_hash(&self) -> <inner>` method to hash newtypes.

# 0.7.2 - 2019-11-29

* Make the inner variable of `sha256::Midstat` public
* Drop the `byteorder` dependency in favor of manual endianness implementations
(later this will be in stdlib so we can drop even that)
* Fix the `hash_newtype` macro, which did not compile before

# 0.7.1 - 2019-08-14

* Add hash_newtype macro that allows third parties to create newtype structs.

# 0.7.0 - 2019-07-19

* Add `hex::Error` type for errors generated by the `hex` module.

# 0.6.0 - 2019-07-10

* Add `no_std` support, rearrange traits to not depend on `io::Write`

# 0.5.0 - 2019-06-28

* Fix panic when parsing hashes that contain multibyte characters
* Add `FromStr` to all hashes which hex-parses them

# 0.4.0 - 2019-06-23

* [Add `from_inner` method](https://github.com/rust-bitcoin/bitcoin_hashes/pull/20) to all hashes
* [Update `FromHex` trait](https://github.com/rust-bitcoin/bitcoin_hashes/pull/40) to require `from_byte_iter` method rather than `from_hex` be implemented
* Make `Hmac` midstate [an actual HMAC midstate](https://github.com/rust-bitcoin/bitcoin_hashes/pull/43)
* Allow `Display` [of truncated hashes](https://github.com/rust-bitcoin/bitcoin_hashes/pull/9)
* Require [using a constructor for `HexIterator`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/44) and then [clean up the internals](https://github.com/rust-bitcoin/bitcoin_hashes/pull/47)
* [Strongly type `sha256::Midstate`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/39) to allow independent serialization
* Add [siphash24 module](https://github.com/rust-bitcoin/bitcoin_hashes/pull/46)

# 0.3.2 - 2019-03-20

* Implement the `FromHex` trait on [many more types](https://github.com/rust-bitcoin/bitcoin_hashes/pull/38)

# 0.3.1 - 2019-03-04

* [Fix serde serialization](https://github.com/rust-bitcoin/bitcoin_hashes/pull/36)

# 0.3.0 - 2019-01-23

* Bump minimum required rustc version to 1.22.0
* Fixed serde deserialization into owned string that previously caused panics
  when doing round-trip (de)serialization
* `HashEngine::block_size()` and `Hash::len()` are now associated constants
  `HashEngine::BLOCK_SIZE` and `Hash::LEN`
* Removed `block_size()` method from `Hash` trait. It is still available as
  `<T as Hash>::Engine::BLOCK_SIZE`

# 0.2.0 - 2019-01-15

* Add a constant-time comparison function
* Simplify `io::Write::write` implementations by having them do only partial writes
* Add fuzzing support
* Allow `Hash`es to be borrowed as `[u8]`
* Replace public `Hash` inners with `into_inner` method

# 0.1.0 - 2018-12-08

* Initial release
