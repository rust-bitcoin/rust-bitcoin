# 0.1.0 - 2026-02-17

It was found that the `1.0.0-rc.x` releases were troublesome because
of how `cargo` resolves version numbers that include a suffix. For
this reason we elected to go back to pre-1.0 version numbers.

`v0.1.0` is a re-release of `v1.0.0-rc.3`

- Add array ref encoder [#5572](https://github.com/rust-bitcoin/rust-bitcoin/pull/5572)
- Introduce lifetimes to all public Encoders [#5556](https://github.com/rust-bitcoin/rust-bitcoin/pull/5556)
- Add `flush_to_*` functions [#5534](https://github.com/rust-bitcoin/rust-bitcoin/pull/5534)
- Add `ExactSizeEncoder` for known-length Encoders [#5445](https://github.com/rust-bitcoin/rust-bitcoin/pull/5445)

# 1.0.0 Release Candidates - 2025-10-10

This changelog is a rolling description of everything that will eventually end up in `v1.0`.

This was truly a team effort, notably @nyonson and @jrakibi. Also please note that many of the ideas
and a bunch of the code, pulled out of a draft PR by @kixunil. Initial implementation was put up by
@apoelstra, then the crew hacked on it while we all reviewed. Good effort team. Also it should be
noted that Kix was pushing for this work for a long time and we all resisted doing it. Now he is not
around but the work got done. Props to him for many of the ideas.

- Fix `consensus-encoding` package name [#5090](https://github.com/rust-bitcoin/rust-bitcoin/pull/5090)
- Introduce pull encoding and use it for blockhash computation [#4912](https://github.com/rust-bitcoin/rust-bitcoin/pull/4912)
- Implement `SliceEncoder` [#4982](https://github.com/rust-bitcoin/rust-bitcoin/pull/4982)
- Add decoder I/O drivers [#5030](https://github.com/rust-bitcoin/rust-bitcoin/pull/5030)
- Tag composers with inline [#5037](https://github.com/rust-bitcoin/rust-bitcoin/pull/5037)
- Clean up encoders unit tests and fix empty `SliceEncoder` [#5039](https://github.com/rust-bitcoin/rust-bitcoin/pull/5039)
- Add encoder composition unit tests [#5045](https://github.com/rust-bitcoin/rust-bitcoin/pull/5045)
- Implement additional decoders [#5057](https://github.com/rust-bitcoin/rust-bitcoin/pull/5057)
- Add `CompactSizeEncoder` and refactor `WitnessEncoder` [#5086](https://github.com/rust-bitcoin/rust-bitcoin/pull/5086)
- Add `new()` constructor to `CompactSizeDecoder` [#5089](https://github.com/rust-bitcoin/rust-bitcoin/pull/5089)
- Remove `prefix_read` field [#5079](https://github.com/rust-bitcoin/rust-bitcoin/pull/5079)
- Remove length prefix from the `BytesEncoder` [#5103](https://github.com/rust-bitcoin/rust-bitcoin/pull/5103)
- Remove length prefix from `SliceEncoder` [#5108](https://github.com/rust-bitcoin/rust-bitcoin/pull/5108)
- Rename `min_bytes_needed` to `read_limit` [#5107](https://github.com/rust-bitcoin/rust-bitcoin/pull/5107)
- Remove transitioning state [#5130](https://github.com/rust-bitcoin/rust-bitcoin/pull/5130)
- Composite decoder errors [#5131](https://github.com/rust-bitcoin/rust-bitcoin/pull/5131)

## 0.0.0 - Placeholder release

Empty crate to reserve the name on crates.io