# 0.5.0 - 2026-01-08

It was found that the `1.0.0-rc.x` releases were troublesome because
of how `cargo` resolves version numbers that include a suffix. For
this reason we elected to go back to pre-1.0 version numbers.

`v0.5.0` is a re-release of `v0.4.0-rc.0`. The only change is to
update the other `rust-bitcoin` repo dependencies.

# 0.4.0-rc.0 - 2025-12-29

* Upgrade dependencies: `bitcoin-internals`, `bitcoin-consensus-encoding`, and `bitcoin_hashes`.

# 0.3.0 - 2025-12-01

* Bump MSRV to Rust `1.74` [#4926](https://github.com/rust-bitcoin/rust-bitcoin/pull/)
* Make traits dyn compatible [#5249](https://github.com/rust-bitcoin/rust-bitcoin/pull/5249)
* Invert dependency between `io` and `hashes` [#3961](https://github.com/rust-bitcoin/rust-bitcoin/pull/3961)
* Introduce `encode_to_writer` for `Write` trait [#5214](https://github.com/rust-bitcoin/rust-bitcoin/pull/5214)
* Add consensus decoding functions [#5212](https://github.com/rust-bitcoin/rust-bitcoin/pull/5212)
* Remove assertion in `Cursor` when reading past end [#5062](https://github.com/rust-bitcoin/rust-bitcoin/pull/5062)
* Enable features in internals crate [#4890](https://github.com/rust-bitcoin/rust-bitcoin/pull/4890)
* Make `io::Error` `Sync` [#3920](https://github.com/rust-bitcoin/rust-bitcoin/pull/3920)
* Use `get_ref` / `get_mut` API [#3855](https://github.com/rust-bitcoin/rust-bitcoin/pull/3855)

# 0.2.0 - 2024-09-18

* Add blanket impl of io traits for `&mut T` [#3188](https://github.com/rust-bitcoin/rust-bitcoin/pull/3188)
* Add `std` bridge [#3176](https://github.com/rust-bitcoin/rust-bitcoin/pull/3176)
* Bump MSRV to Rust `v1.63.0` [#3100](https://github.com/rust-bitcoin/rust-bitcoin/pull/3100)
* Remove blanket trait impls [#2453](https://github.com/rust-bitcoin/rust-bitcoin/pull/2453)

# 0.1.3 - 2024-11-02

* Backport IO improvements [#3181](https://github.com/rust-bitcoin/rust-bitcoin/pull/3181)
  (Original PR: [#3176](https://github.com/rust-bitcoin/rust-bitcoin/pull/3176))

# 0.1.2 - 2024-03-14

* Implement `From<core::convert::Infallible>` for Errors [#2516](https://github.com/rust-bitcoin/rust-bitcoin/pull/2516)
* Fix new CI build warnings [#2488](https://github.com/rust-bitcoin/rust-bitcoin/pull/2488)

# 0.1.1 - Initial Release - 2024-02-18

Create the `io` crate, add basic I/O traits, types, and implementations.

Traits:

- `Read`
- `BufRead`
- `Write`

Types:

- `Take`
- `Cursor`
- `Sink`

# 0.1.0 - Placeholder release

Empty crate to reserve the name on crates.io