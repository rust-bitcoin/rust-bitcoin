# Contributing to rust-bitcoin

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to Rust Bitcoin
implementation and other Rust Bitcoin-related projects, which are hosted in the
[Rust Bitcoin Community](https://github.com/rust-bitcoin) on GitHub. These are
mostly guidelines, not rules. Use your best judgment, and feel free to propose
changes to this document in a pull request.

#### Table Of Contents

- [General](#general)
- [Communication channels](#communication-channels)
- [Asking questions](#asking-questions)
- [Contribution workflow](#contribution-workflow)
  * [Preparing PRs](#preparing-prs)
  * [Peer review](#peer-review)
  * [Repository maintainers](#repository-maintainers)
- [Coding conventions](#coding-conventions)
  * [Naming conventions](#naming-conventions)
  * [Upgrading dependencies](#upgrading-dependencies)
  * [Unsafe code](#unsafe-code)
  * [Policy](#policy)
- [Security](#security)
- [Testing](#testing)
- [Going further](#going-further)


## General

The Rust Bitcoin project operates an open contributor model where anyone is
welcome to contribute towards development in the form of peer review,
documentation, testing and patches.

Anyone is invited to contribute without regard to technical experience,
"expertise", OSS experience, age, or other concern. However, the development of
standards & reference implementations demands a high-level of rigor, adversarial
thinking, thorough testing and risk-minimization. Any bug may cost users real
money. That being said, we deeply welcome people contributing for the first time
to an open source project or pick up Rust while contributing. Don't be shy,
you'll learn.


## Communication channels

Communication about Rust Bitcoin happens primarily in
[#bitcoin-rust](https://web.libera.chat/?channel=#bitcoin-rust) IRC chat on
[Libera](https://libera.chat/) with the logs available at
<https://gnusha.org/bitcoin-rust/> (starting from Jun 2021 and now on) and
<https://gnusha.org/rust-bitcoin/> (historical archive before Jun 2021).

Discussion about code base improvements happens in GitHub issues and on pull
requests.

Major projects are tracked [here](https://github.com/orgs/rust-bitcoin/projects).
Major milestones are tracked [here](https://github.com/rust-bitcoin/rust-bitcoin/milestones).


## Asking questions

> **Note:** Please don't file an issue to ask a question. You'll get faster
> results by using the resources below.

We have a dedicated developer channel on IRC, #bitcoin-rust@libera.chat where
you may get helpful advice if you have questions.


## Contribution workflow

The codebase is maintained using the "contributor workflow" where everyone
without exception contributes patch proposals using "pull requests". This
facilitates social contribution, easy testing and peer review.

To contribute a patch, the workflow is a as follows:

1. Fork Repository
2. Create topic branch
3. Commit patches

Please keep commits should atomic and diffs easy to read. For this reason
do not mix any formatting fixes or code moves with actual code changes.
Further, each commit, individually, should compile and pass tests, in order to
ensure git bisect and other automated tools function properly.

Please cover every new feature with unit tests.

When refactoring, structure your PR to make it easy to review and don't hesitate
to split it into multiple small, focused PRs.

Commits should cover both the issue fixed and the solution's rationale.
Please keep these [guidelines](https://chris.beams.io/posts/git-commit/) in mind.

To facilitate communication with other contributors, the project is making use
of GitHub's "assignee" field. First check that no one is assigned and then
comment suggesting that you're working on it. If someone is already assigned,
don't hesitate to ask if the assigned party or previous commenters are still
working on it if it has been awhile.


## Preparing PRs

The main library development happens in the `master` branch. This branch must
always compile without errors (using GitHub CI). All external contributions are
made within PRs into this branch.

Prerequisites that a PR must satisfy for merging into the `master` branch:
* each commit within a PR must compile and pass unit tests with no errors, with
  every feature combination (including compiling the fuzztests) on some
  reasonably recent compiler (this is partially automated with CI, so the rule
  is that we will not accept commits which do not pass GitHub CI);
* the tip of any PR branch must also compile and pass tests with no errors on
  MSRV (check [README.md] on current MSRV requirements) and pass fuzz tests on
  nightly rust;
* contain all necessary tests for the introduced functional (either as a part of
  commits, or, more preferably, as separate commits, so that it's easy to
  reorder them during review and check that the new tests fail without the new
  code);
* contain all inline docs for newly introduced API and pass doc tests;
* be based on the recent `master` tip from the original repository at
  <https://github.com/rust-bitcoin/rust-bitcoin>.

NB: reviewers may run more complex test/CI scripts, thus, satisfying all the
requirements above is just a preliminary, but not necessary sufficient step for
getting the PR accepted as a valid candidate PR for the `master` branch.

PR authors may also find it useful to run the following script locally in order
to check that each of the commits within the PR satisfies the requirements
above, before submitting the PR to review:
```shell script
RUSTUP_TOOLCHAIN=1.41.1 ./contrib/test.sh
```
Please replace the value in `RUSTUP_TOOLCHAIN=1.41.1` with the current MSRV from
[README.md].

NB: Please keep in mind that the script above replaces `Cargo.lock` file, which
is necessary to support current MSRV, incompatible with `stable` and newer cargo
versions.

### Peer review

Anyone may participate in peer review which is expressed by comments in the pull
request. Typically, reviewers will review the code for obvious errors, as well as
test out the patch set and opine on the technical merits of the patch. Please,
first review PR on the conceptual level before focusing on code style or
grammar fixes.

### Repository maintainers

Pull request merge requirements:
- all CI test should pass,
- at least two "accepts"/ACKs from the repository maintainers (see "refactor carve-out").
- no reasonable "rejects"/NACKs from anybody who reviewed the code.

Current list of the project maintainers:

- [Andrew Poelstra](https://github.com/apoelstra)
- [Steven Roose](https://github.com/stevenroose)
- [Matt Corallo](https://github.com/TheBlueMatt)
- [Elichai Turkel](https://github.com/elichai)
- [Sanket Kanjalkar](https://github.com/sanket1729)
- [Martin Habovštiak](https://github.com/Kixunil)
- [Riccardo Casatta](https://github.com/RCasatta)
- [Tobin Harding](https://github.com/tcharding)

#### Refactor carve-out

The repository is going through heavy refactoring and "trivial" API redesign
(eg, rename `Foo::empty` to `Foo::new`) as we push towards API stabilization. As
such reviewers are either bored or overloaded with notifications, hence we have
created a carve out to the 2-ACK rule.

A PR may be considered for merge if it has a single ACK and has sat open for at
least two weeks with no comments, questions, or NACKs.

#### One ACK carve-out

We reserve the right to merge PRs with a single ACK [0], at any time, if they match
any of the following conditions:

1. PR only touches CI i.e, only changes any of the `test.sh` scripts and/or
   stuff in `.github/workflows`.
2. Non-content changing documentation fixes i.e., grammar/typos, spelling, full
   stops, capital letters. Any change with more substance must still get two
   ACKs.
3. Code moves that do not change the API e.g., moving error types to a private
   submodule and re-exporting them from the original module. Must not include
   any code changes except to import paths. This rule is more restrictive than
   the refactor carve-out. It requires absolutely no change to the public API.

[0] - Obviously author and ACK'er must not be the same person.

## Coding conventions

Library reflects Bitcoin Core approach whenever possible.

### Naming conventions

Naming of data structures/enums and their fields/variants must follow names used
in Bitcoin Core, with the following exceptions:
- the case should follow Rust standards (i.e. PascalCase for types and
  snake_case for fields and variants);
- omit `C`-prefixes.

### Upgrading dependencies

If your change requires a dependency to be upgraded you must do the following:

1. Modify `Cargo.toml`
2. Copy `Cargo-minimal.lock` to `Cargo.lock`
3. Trigger cargo to update the required entries in the lock file - use `--precise` using the minimum version number that works
4. Test your change
5. Copy `Cargo.lock` to `Cargo-minimal.lock`
6. Update `Cargo-recent.lock` if it is also behind
7. Commit both lock files together with `Cargo.toml` and your code changes

### Unsafe code

Use of `unsafe` code is prohibited unless there is a unanimous decision among
library maintainers on the exclusion from this rule. In such cases there is a
requirement to test unsafe code with sanitizers including Miri.


### Policy

We have various `rust-bitcoin` specific coding styles and conventions that are
grouped here loosely under the term 'policy'. These are things we try to adhere
to but that you should not need to worry too much about if you are a new
contributor. Think of this as a place to collect group knowledge that exists in
the various PRs over the last few years.

#### Import statements

We use the following style for import statements, see
(https://github.com/rust-bitcoin/rust-bitcoin/discussions/2088) for the discussion that led to this.

```rust

// Modules first, as they are part of the project's structure.
pub mod aa_this;
mod bb_private;
pub mod cc_that;

// Private imports, rustfmt will sort and merge them correctly.
use crate::aa_this::{This, That};
use crate::bb_that;

// Public re-exports.
#[rustfmt::skip] // Keeps public re-exports separate, because of this we have to sort manually.
pub use {
    crate::aa_aa_this,
    crate::bb_bb::That,
}
```

#### Return `Self`

Use `Self` as the return type instead of naming the type. When constructing the return value use
`Self` or the type name, whichever you prefer.

```rust
/// A counter that is always smaller than 100.
pub struct Counter(u32);

impl Counter {
    /// Constructs a new `Counter`.
    pub fn new() -> Self { Self(0) }

    /// Returns a counter if it is possible to create one from x.
    pub fn maybe(x: u32) -> Option<Self> {
        match x {
            x if x >= 100 => None,
            c => Some(Counter(c)),
        }
    }
}

impl TryFrom<u32> for Counter {
    type Error = TooBigError;

    fn try_from(x: u32) -> Result<Self, Self::Error> {
        if x >= 100 {
            return Err(TooBigError);
        }
        Ok(Counter(x))
    }
}
```

When constructing the return value for error enums use `Self`.

```rust
impl From<foo::Error> for LongDescriptiveError {
    fn from(e: foo::Error) -> Self { Self::Foo(e) }
}
```


#### Errors

Return as much context as possible with errors e.g., if an error was encountered parsing a string
include the string in the returned error type. If a function consumes costly-to-compute input
(allocations are also considered costly) it should return the input back in the error type.

More specifically an error should

- be `non_exhaustive` unless we _really_ never want to change it.
- have private fields unless we are very confident they won't change.
- derive `Debug, Clone, PartialEq, Eq` (and `Copy` iff not `non_exhaustive`).
- implement Display using `write_err!()` macro if a variant contains an inner error source.
- have `Error` suffix
- implement `std::error::Error` if they are public (feature gated on "std").

```rust
/// Documentation for the `Error` type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]  // Add liberally; if the error type may ever have new variants added.
pub enum Error {
    /// Documentation for variant A.
    A,
    /// Documentation for variant B.
    B,
}
```


#### Rustdocs

Be liberal with references to BIPs or other documentation; the aim is that devs can learn about
Bitcoin by hacking on this codebase as opposed to having to learn about Bitcoin first and then start
hacking on this codebase. Consider the following format, not all sections will be required for all types.


```rust
/// The Bitcoin foobar.
///
/// Contains all the data used when passing a foobar around the Bitcoin network.
///
/// <details>
/// <summary>FooBar Original Design</summary>
///
/// The foobar was introduced in Bitcoin x.y.z to increase the amount of foo in bar.
///
/// </details>
///
/// ### Relevant BIPs
///
/// * [BIP X - FooBar in Bitcoin](https://github.com/bitcoin/bips/blob/master/bip-0000.mediawiki)
pub struct FooBar {
    /// The version in use.
    pub version: Version
}
```

Do use rustdoc subheadings. Do put an empty newline below each heading e.g.,

```rust
impl FooBar {
    /// Constructs a `FooBar` from a [`Baz`].
    ///
    /// # Errors
    ///
    /// Returns an error if `Baz` is not ...
    ///
    /// # Panics
    ///
    /// If the `Baz`, converted to a `usize`, is out of bounds.
    pub fn from_baz(baz: Baz) -> Result<Self, Error> {
        ...
    }
}
```

Add Panics section if any input to the function can trigger a panic.

Generally we prefer to have non-panicking APIs but it is impractical in some cases. If you're not
sure, feel free to ask. If we determine panicking is more practical it must be documented. Internal
panics that could theoretically occur because of bugs in our code must not be documented.


#### Derives

We try to use standard set of derives if it makes sense:

```
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Foo {
    Bar,
    Baz,
}
```

For types that do should not form a total or partial order, or that technically do but it does not
make sense to compare them, we use the `Ordered` trait from the
[`ordered`](https://crates.io/crates/ordered) crate. See `absolute::LockTime` for an example.

For error types you likely want to use `#[derive(Debug, Clone, PartialEq, Eq)]`.

See [Errors](#errors) section.


#### Attributes

- `#[track_caller]`: Used on functions that panic on invalid arguments
  (see https://rustc-dev-guide.rust-lang.org/backend/implicit-caller-location.html)

- `#[cfg(rust_v_1_60)]`: Used to guard code that should only be built in if the toolchain is
  compatible. These configuration conditionals are set at build time in `bitcoin/build.rs`. New
  version attributes may be added as needed.


#### Licensing

We use SPDX license tags, all files should start with

```
// SPDX-License-Identifier: CC0-1.0
```

## Security

Security is the primary focus for this library; disclosure of security
vulnerabilities helps prevent user loss of funds. If you believe a vulnerability
may affect other implementations, please disclose this information according to
the [security guidelines](./SECURITY.md), work on which is currently in progress.
Before it is completed, feel free to send disclosure to Andrew Poelstra,
apoelstra@wpsoftware.net, encrypted with his public key from
<https://www.wpsoftware.net/andrew/andrew.gpg>.


## Testing

Related to the security aspect, rust bitcoin developers take testing very
seriously. Due to the modular nature of the project, writing new test cases is
easy and good test coverage of the codebase is an important goal. Refactoring
the project to enable fine-grained unit testing is also an ongoing effort.

Various methods of testing are in use (e.g. fuzzing, mutation), please see
the [readme](./README.md) for more information.


## Going further

You may be interested in the guide by Jon Atack on
[How to review Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md)
and [How to make Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md).
While there are differences between the projects in terms of context and
maturity, many of the suggestions offered apply to this project.

Overall, have fun :)
