# 0.4.0 - 2024-09-18

- Introduce `ToU64` trait [#2929](https://github.com/rust-bitcoin/rust-bitcoin/pull/2929)
- Add macro `impl_to_hex_from_lower_hex ` [#3150](https://github.com/rust-bitcoin/rust-bitcoin/pull/3150)
- Fix bug in `ArrayVec::extend_from_slice` [#3272](https://github.com/rust-bitcoin/rust-bitcoin/pull/3272)
- Introduce `read_push_data_len()` and [#3293](https://github.com/rust-bitcoin/rust-bitcoin/pull/3293/)
- Introduce new `compact_size` module [#3259](https://github.com/rust-bitcoin/rust-bitcoin/pull/3259)

# 0.3.0 - 2024-03-24

- Bump MSRV to Rust version 1.56.1 [#2188](https://github.com/rust-bitcoin/rust-bitcoin/pull/2188)
- Implement custom `ArrayVec` that is `Copy` [#2287](https://github.com/rust-bitcoin/rust-bitcoin/pull/2287)

# 0.2.0 - 2023-06-20

- [Rename crate](https://github.com/rust-bitcoin/rust-bitcoin/pull/1885) to `bitcoin-internals`
- Add module to assist [alloc-free parse error handling](https://github.com/rust-bitcoin/rust-bitcoin/pull/1297)
- Move various macros here.

# 0.1.0 - 2023-03-08

Split this crate out from the [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) crate.
For previous development history see the original
[CHANGELOG](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/CHANGELOG.md) file.
