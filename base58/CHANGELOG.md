# 0.2.0 - 2024-12-10

- Bump MSRV to `1.63` [#3100](https://github.com/rust-bitcoin/rust-bitcoin/pull/3100)
- Optimize `base58` on small inputs [#3002](https://github.com/rust-bitcoin/rust-bitcoin/pull/3002)
- Add `alloc` feature [#2996](https://github.com/rust-bitcoin/rust-bitcoin/pull/2996)
- Remove zeroed vector by pushing front [#3227](https://github.com/rust-bitcoin/rust-bitcoin/pull/3227)
- Close all errors [#3533](https://github.com/rust-bitcoin/rust-bitcoin/pull/3533)
- Bump `hex-conservative` to `0.3.0` [#3543](https://github.com/rust-bitcoin/rust-bitcoin/pull/3543)

# 0.1.0 - 2024-03-14

Initial release of the `base58ck` crate. This crate was cut out of
`rust-bitcoin` and cleaned up for release as a separate crate.
