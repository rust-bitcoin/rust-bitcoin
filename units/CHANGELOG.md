# 0.2.0 - 2024-09-18

* Bump MSRV to 1.63.0 [#3100](https://github.com/rust-bitcoin/rust-bitcoin/pull/3100)
* Remove re-export of `ParseIntError` [#3069](https://github.com/rust-bitcoin/rust-bitcoin/pull/3069)
* Improve docs [#2957](https://github.com/rust-bitcoin/rust-bitcoin/pull/2957)
* Fix `Amount` decimals handling [#2951](https://github.com/rust-bitcoin/rust-bitcoin/pull/2951)
* Remove `Denomination::MilliSatoshi` [#2870](https://github.com/rust-bitcoin/rust-bitcoin/pull/2870)
* Document that the implementation of `Display` for `Amount` is unstable [#3323](https://github.com/rust-bitcoin/rust-bitcoin/pull/3323)
* Add a condition for parsing zero from string when not denominated [#3346](https://github.com/rust-bitcoin/rust-bitcoin/pull/3346)
* Enforce displaying `Amount` with trailing zeros [#2604](https://github.com/rust-bitcoin/rust-bitcoin/pull/2604)
* Fix `Amount` decimals handling [#2951](https://github.com/rust-bitcoin/rust-bitcoin/pull/2951)
* Error instead of panic when `Time::from_second_ceil` input is too large [#3052](https://github.com/rust-bitcoin/rust-bitcoin/pull/3052)
* Remove re-export of `ParseIntError` [#3069](https://github.com/rust-bitcoin/rust-bitcoin/pull/3069)
* Add `FeeRate` addition and subtraction traits [#3381](https://github.com/rust-bitcoin/rust-bitcoin/pull/3381)

## Additional test infrastructure:`Arbitrary`

This release we started adding implementations of
[`arbitrary::Arbitrary`](https://docs.rs/arbitrary/latest/arbitrary/trait.Arbitrary.html).

Types implemented: `Amount`, `SignedAmount`, `FeeRate`, and `Weight`.

In the following PRs:

* [#3305](https://github.com/rust-bitcoin/rust-bitcoin/pull/3015)
* [#3257](https://github.com/rust-bitcoin/rust-bitcoin/pull/3257)
* [#3247](https://github.com/rust-bitcoin/rust-bitcoin/pull/3274)

## 0.1.2 - 2024-07-01

* Remove enable of `alloc` feature in the `internals` dependency.

Note, the bug fixed by this release was introduced in
[#2655](https://github.com/rust-bitcoin/rust-bitcoin/pull/2655) and
was incorrect because we have an `alloc` feature that enables
`internals/alloc`.

`v0.1.1` will be yanked for this reason.

## 0.1.1 - 2024-04-04

* Enable "alloc" feature for `internals` dependency - enables caching
  of parsed input strings in a couple of `amount` error types.

## 0.1.0 - Initial Release - 2024-04-03

Initial release of the `bitcoin-units` crate. These unit types are
integer wrapper types used by the `rust-bitcoin` ecosystem. Note
please that this release relies heavily on the "alloc" feature.

The main types are:

- `Amount`
- `locktime::absolute::{Height, Time}`
- `locktime::relative::{Height, Time}`
- `FeeRate`
- `Weight`

## 0.0.0 - Placeholder release

Empty crate to reserve the name on crates.io