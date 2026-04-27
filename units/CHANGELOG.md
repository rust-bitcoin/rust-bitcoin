
# Unreleased

* Add optional `bitcoin-consensus-encoding` support for `Amount` on Rust 1.65+.

# 0.1.3 - 2026-04-19

* Backport `Arbitrary` to `0.32.x` [#5085](https://github.com/rust-bitcoin/rust-bitcoin/pull/5085)
* Backport: Add CompactSize range check to deserialization [#5921](https://github.com/rust-bitcoin/rust-bitcoin/pull/5921)

# 0.1.2 - 2024-07-01

* Remove enable of `alloc` feature in the `internals` dependency.

Note, the bug fixed by this release was introduced in
[#2655](https://github.com/rust-bitcoin/rust-bitcoin/pull/2655) and
was incorrect because we have an `alloc` feature that enables
`internals/alloc`.

`v0.1.1` will be yanked for this reason.

# 0.1.1 - 2024-04-04

* Enable "alloc" feature for `internals` dependency - enables caching
  of parsed input strings in a couple of `amount` error types.

# 0.1.0 - Initial Release - 2024-04-03

Initial release of the `bitcoin-units` crate. These unit types are
integer wrapper types used by the `rust-bitcoin` ecosystem. Note
please that this release relies heavily on the "alloc" feature.

The main types are:

- `Amount`
- `locktime::absolute::{Height, Time}`
- `locktime::relative::{Height, Time}`
- `FeeRate`
- `Weight`

# 0.0.0 - Placeholder release

Empty crate to reserve the name on crates.io
