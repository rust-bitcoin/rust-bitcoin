# consensus_encoding crate for sans-I/O

* Status: accepted
* Authors: Andrew Poelstra
* Date: 2025-09-06
* Targeted modules: `consensus_encoding`, `primitives`, `units`
* Associated tickets/PRs: #4912

## Context and Problem Statement

The rust-bitcoin project needs a way to perform consensus encoding/decoding operations without depending on std. The existing consensus encoding approach is somewhat tied to the `std::io` interfaces, but in order to make it no-std compatible, the `bitcoin-io` crate was introduced with "bridges" to the std I/O traits. But despite the best efforts of the bridges, there is still a lot of caller friction. Plus there is a requirement to always deal with I/O errors even in non-I/O contexts (e.g. hashing an encoding).

Is there a way to better support encoding in no-std, std, non-I/O, and even async contexts?

## Decision Drivers

* Support no_std environments.
* Reduce API friction.
* Eliminate I/O errors in non-I/O contexts.

## Considered Options

#### Option 1: Roll with the existing bitcoin-io crate

The crate has its pain points, but it gets the job done.

**Pros:**

* Maintains existing API surface.

**Cons:**

* Pain points for the general `std::io` case and error handling remain.
* The interface would be tied to the v1.0.0 release of the `primitives` and `units` crates, requiring maintenance support for a very long time.

#### Option 2: Adopt the push_decode crate

Martin Habovštiak wrote a general purpose sans-I/O encoding/decoding crate, [`push_decode`], which satisfies the technical requirements.

**Pros:**

* Already written.
* Removes ties to std I/O and I/O errors.

**Cons:**

* Is general purpose, so has a few layers of abstraction and complexity not required in the bitcoin domain.

#### Option 3: Create dedicated consensus_encoding crate

Extract consensus encoding/decoding logic into a new crate which is sans-I/O and focused only on the bitcoin domain.

**Pros:**

* Removes ties to std I/O and I/O errors.
* Interface is tailored for the bitcoin domain.

**Cons:**

* Requires most amount of new code to write and maintain.

## Decision Outcome

Option #3, dedicated `consensus_encoding` crate. While it is new code, it is heavily based on [`push_decode`] and slimmed down to just what is required in the workspace. It supports no-std, std, non-I/O, and could support async contexts. It should be relatively cheap to maintain given the limited domain.

## Links

* Initial implementation in [#4912].
* First release in [#5160].

[#4912]: <https://github.com/rust-bitcoin/rust-bitcoin/pull/4912>
[#5160]: <https://github.com/rust-bitcoin/rust-bitcoin/pull/5160>
[`push_decode`]: <https://github.com/Kixunil/push_decode>
