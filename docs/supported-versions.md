# Supported versions

List of crates, their versions that we still actively maintain, and the dependency versions.

## Bitcoin LTS versions

- `v0.30` (Security and bug fixes only)
- `v0.31` (Security and bug fixes only)
- `v0.32`

`v0.32` is the version most of the eccosystem is on. It is actively maintained. This means:

1. Will backport anything that is easy enough if requested and if possible within semver rules.
2. May attempt more involved backport work if we deem it important enough.
3. Backport deprecations where possible as the API is developed to assist upgrade path.
4. Security and bug fixes, obviously.

(1) includes new features developed on `master`, so contributors are welcome to contribute a new
feature with the explicit aim of then backporting it to `0.32`.

## Dependency version map

The LTS `bitcoin` releases and dependency versions (of crates in this repository).

- `bitcoin 0.30`
  -> `bitcoin-private 0.1`
  -> `hashes 0.12`

- `bitcoin 0.31`
  -> `internals 0.2`
  -> `hashes 0.13`

- `bitcoin 0.32`
  -> `base58ck 0.1`
  -> `internals 0.3`
  -> `io 0.1`
  -> `units 0.1`
  -> `hashes 0.14`

Currently in development:

- `bitcoin 0.33-rc.x`
  -> `hashes 0.17`
  -> `io 0.2`
  -> `internals 0.4`
  -> `primitives-1.0.0-rc.x`
  -> `units-1.0.0-rc.x`
  -> (transitively `consensus-encoding 1.0.0-rc.x`)

Once the RC cycle is done:

- `bitcoin 0.33`
  -> `hashes 0.17`
  -> `io 0.2`
  -> `internals 0.4`
  -> `primitives-1.0.0`
  -> `units-1.0.0`
  -> `consensus-encoding 1.0.0`
