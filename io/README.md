Rust-Bitcoin IO Library
=======================

The `std::io` module is not exposed in `no-std` Rust so building `no-std` applications which require
reading and writing objects via standard traits is not generally possible. Thus, this library exists
to export a minmal version of `std::io`'s traits which we use in `rust-bitcoin` so that we can
support `no-std` applications.

These traits are not one-for-one drop-ins, but are as close as possible while still implementing
`std::io`'s traits without unnecessary complexity.
