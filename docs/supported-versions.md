# Supported Versions

Three versions of the `bitcoin` crate are supported, the current in development version and two Long-Term Support (LTS) versions.

Because the `bitcoin` crate is an umbrella across the rest of the crates in the workspace, the oldest LTS version's minimum dependencies determine the LTS versions of the other crates.

LTS versions are actively maintained and receive updates like the following.

1. Will backport anything that is easy enough if requested and if possible within semver rules.
2. May attempt more involved backport work if we deem it important enough.
3. Backport deprecations where possible as the API is developed to assist upgrade path.
4. Security and bug fixes, obviously.

(1) includes new features developed on `master`, so contributors are welcome to contribute a new
feature with the explicit aim of then backporting to LTS branches.

## `bitcoin` LTS Versions

- `v0.32.100+` -- MSRV of `1.60.0` and the optional `encoding` feature.
- `v0.32.10+` -- MSRV of `1.56.1`.

As of 2026-07-07, `v0.32` is the version most of the ecosystem is on and is actively maintained. Due to its longevity, we are in the unconventional spot of maintaining two branches of `v0.32` in an effort to make it easier for users to migrate to the stabilized crates.
