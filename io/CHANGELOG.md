# 0.2.0 - 2024-09-18

* Add blanket impl of io traits for `&mut T` [#3188](https://github.com/rust-bitcoin/rust-bitcoin/pull/3188)
* Add `std` bridge [#3176](https://github.com/rust-bitcoin/rust-bitcoin/pull/3176)
* Bump MSRV to Rust `v1.63.0` [#3100](https://github.com/rust-bitcoin/rust-bitcoin/pull/3100)
* Remove blanket trait impls [#2453](https://github.com/rust-bitcoin/rust-bitcoin/pull/2453)

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