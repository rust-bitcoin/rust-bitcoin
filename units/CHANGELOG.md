# 1.0.0-alpha - 2025-01-20

BOOM! A long time in the making but here goes, our first alpha 1.0 crate release.

* Add `FIFTY_BTC` const to the amount types [#3915](https://github.com/rust-bitcoin/rust-bitcoin/pull/3915)
* Remove `InputString` from the public API [#3905](https://github.com/rust-bitcoin/rust-bitcoin/pull/)
* Hide the remaining public macros [#3867]()
* Introduce an unchecked constructor for the `Amount` type [#3811]()
* Implement `Arbitrary` for `units` types [#3777]()
* Change method return type for `to_unsigned()` [#3769]()
* Change paramater type used for whole bitcoin [#3744]()
* Add `Weight::to_kwu_ceil` [#3740]()
* Change `SignedAmount` MAX and MIN to equal +/- MAX_MONEY [#3719]()
* Change `Amount::MAX` from `u64::MAX` to `Amount::MAX_MONEY` [#3693]()
* Support serde serializing `Amount` as string [#3679]()
* Close amounts error types [#3674]()
* Close the hex parse errors [#3673]()
* Remove `serde` from amounts [#3672]()
* Implement `serde` modules for `FeeRate` [#3666]()
* Remove `Amount::fmt_value_in` [#3621]()
* Split `checked_div_by_weight` into floor and ceiling version [#3587]()
* Replace `String` with `InputString` [#3559]()
* Add checked div by weight to amount [#3430]()
* Add `FeeRate` addition and subtraction traits [#3381]()
* Add `Arbitrary` to `SignedAmount` type [#3274]()
* Add `Arbitrary` to `Weight` [#3257]()

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
* Add `BlockHeight` and `BlockInterval` types [#2615](https://github.com/rust-bitcoin/rust-bitcoin/pull/2615)

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