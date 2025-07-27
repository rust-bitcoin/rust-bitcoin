# PSBT

We would like to enable support for PSBTv2, not necessarily add support to `rust-bitcoin`.
Potentially we want to spilt out the current PSBTv1 into a separate crate. The serialization logic
likely stays in `rust-bitcoin`. There are various attempts at this in flight but mostly stale.

* Initial support in `rust-bitcoin`: [#3507](https://github.com/rust-bitcoin/rust-bitcoin/pull/3507)
* Initial PSBTV2 impl: https://github.com/tcharding/rust-psbt
