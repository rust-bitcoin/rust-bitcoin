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
  * [Formatting](#formatting)
  * [Derivation](#derivation)
  * [MSRV](#msrv)
  * [Naming conventions](#naming-conventions)
  * [Unsafe code](#unsafe-code)
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
<http://gnusha.org/rust-bitcoin/>.

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

In general commits should be atomic and diffs should be easy to read. For this
reason do not mix any formatting fixes or code moves with actual code changes.
Further, each commit, individually, should compile and pass tests, in order to
ensure git bisect and other automated tools function properly.

When adding a new feature thought must be given to the long term technical debt.
Every new features should be covered by unit tests.

When refactoring, structure your PR to make it easy to review and don't hesitate
to split it into multiple small, focused PRs.

Commits should cover both the issue fixed and the solution's rationale.
These [guidelines](https://chris.beams.io/posts/git-commit/) should be kept in
mind.

To facilitate communication with other contributors, the project is making use
of GitHub's "assignee" field. First check that no one is assigned and then
comment suggesting that you're working on it. If someone is already assigned,
don't hesitate to ask if the assigned party or previous commenters are still
working on it if it has been awhile.

## Preparing PRs

The main library development happens in the `master` branch. This branch must
always compile without errors (using GitHub CI). All external contributions are
made within PRs into this branch.

Prerequisites that a PR must satisfy in order to be considered for merging into
the `master` branch:
* each commit within a PR must compile and pass unit tests with no errors, with
  every feature combination (including compiling the fuzztests) on some
  reasonably recent compiler (this is partially automated with CI, so the rule
  is that if GitHub CI is not passing, the commit can't be accepted);
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
BITCOIN_MSRV=1.29.0 ./contrib/ci.sh
```
Where value in `BITCOIN_MSRV=1.29.0` should be replaced with the current MSRV
from [README.md].

NB: Please keep in mind that the script above replaces `Cargo.lock` file, which
is necessary to support current MSRV, incompatible with `stable` and newer cargo
versions.

### Peer review

Anyone may participate in peer review which is expressed by comments in the pull
request. Typically, reviewers will review the code for obvious errors, as well as
test out the patch set and opine on the technical merits of the patch. PR should
be reviewed first on the conceptual level before focusing on code style or
grammar fixes.

### Repository maintainers

For the pull request to be merged we require (a) that all CI test should pass
and (2) at least two "accepts"/ACKs from the repository maintainers – and no
main reasonable "rejects"/NACKs from anybody who reviewed the code.

Current list of the project maintainers:

- [Andrew Poelstra](https://github.com/apoelstra)
- [Steven Roose](https://github.com/stevenroose)
- [Maxim Orlovsky](https://github.com/dr-orlovsky)
- [Matt Corallo](https://github.com/TheBlueMatt)
- [Elichai Turkel](https://github.com/elichai)
- [Sebastian Geisler](https://github.com/sgeisler)
- [Sanket Kanjalkar](https://github.com/sanket1729)


## Coding conventions

Overall, this library must reflect Bitcoin Core approach whenever possible.
However, since many of the things in Bitcoin Core are maintained due to
historical reasons and may represent poor design, Rust-idiomatic style is
preferred to "how it looks in Core" if everyone agrees.

### Formatting

We plan to utilize `rustfmt` for keeping the code formatting consistent.
However, this will be a gradual process since a thorough peer review is required
to make sure that no unintended changes are introduced with the change of
formatting. Thus, all PRs introducing large blocks of re-formatted code will not
be reviewed.

The current plan is to phase it in over multiple commits or even multiple PRs,
which will introduce no changes other than re-formatting, such that each change
may be independently re-reproduced by each reviewer. The first commit should add
attributes to disable fmt for some parts of the code and a second one does the
formatting – so only the first one needs review, the rest will be reproducible.

You may check the [discussion on the formatting](https://github.com/rust-bitcoin/rust-bitcoin/issues/172)
and [how it is planned to coordinate it with crate refactoring](https://github.com/rust-bitcoin/rust-bitcoin/pull/525)

Before formatting with `rustfmt` is implemented, it is recommended to follow
style of the existing codebase and avoid any end-line space characters.

<!--
Rust-fmt should be used as a coding style recommendations in general, with a
default coding style. By default, Rustfmt uses a style which conforms to the
[Rust style guide][style guide] that has been formalized through the [style RFC
process][fmt rfcs]. It is also required to run `cargo fmt` to make the code
formatted according to `rustfmt` parameters
-->

### Derivation

Derivations applied to a data structures should be standardized:

1. All non-error types should opportunistically derive, where it is possible,
   the following traits:
   - `Copy` (except iterators)
   - `Clone`
   - `PartialEq` and `Eq`
   - `PartialOrd` and `Ord`
   - `Hash`
   - `Debug`

   By "where possible" we mean that by default a code line
   ```rust
   #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
   ```
   must be placed before each struct, and then those of these traits, which
   can't be auto-derived because of the member field restrictions should be
   removed.

2. `Eq`, `PartialEq`, `Ord`, `PartialOrd` derivation must be skipped/removed
   from pt. 1 in the following situations:
   - for types that don't have reflexive equality/ordering
   - types which have a lexicographic ordering defined as a part of a standard
     must provide a manual implementation
   - types which may be more efficiently compared with bitcoin-specific rules
     should provide a manual implementation

3. `Debug` must not be derived on structs and enums which may contain secret
   data, and a manual `Debug` implementation should be provided instead.

4. `Default` derivation should be performed whenever there is a rationale to
   have default constructor initializing "empty" data structure, i.e. this
   empty structure has a real use in the business logic *outside of the scope
   of testing or creating dumb data*. For instance, if the structure consists
   only of collection types which may be empty it should derive `Default` trait.

5. **Error types** (both structs and enums) must implement `Display` and `Error`
   traits manually, and should provide `Error::source` function if some of the
   error cases contain other error type.

6. `Display` should be implemented for all data types which may be presented to
   the end user (not developers!), for instance in command line or as a part of
   GUI. Here are some guidelines:
   - Normally, `Display` implementation should not just repeat `Debug` and
     structure the data in some visually-acceptable way.
   - One should pay attention to the ability of providing alternative ways of
     data formatting with `{:#}` formatting string option, detectable by
     `std::fmt::Formatter::alternate()` function. Other important options to
     look at are `align`, `fill`, `pad`, `precision` and `width`.
   - When displaying the member fields it is important to consider the ability
     to pass them display formatting options; thus,
     `Display::fmt(&self.field, f)?;` is preferable over
     `write!(f, "{}", self.field)?;`

7. Serde serializers should be implemented for all data types which may persist
   or may be presented in the UI or API as JSON/YAML and other kinds of data
   representations (in fact, these are all data types).

The discussion about trait derivation can be read at
[the tracking issue](https://github.com/rust-bitcoin/rust-bitcoin/issues/555).

### MSRV

The Minimal Supported Rust Version (MSRV) is 1.29; it is enforced by our CI.
Later we plan to increase MSRV to support Rust 2018 and you are welcome to check
the [tracking issue](https://github.com/rust-bitcoin/rust-bitcoin/issues/510).

### Naming conventions

Naming of data structures/enums and their fields/variants must follow names used
in Bitcoin Core, with except to:
- case, which should follow Rust standards (i.e. PascalCase for types and
  snake_case for fields and variants)
- `C`-prefix, which should be omitted

### Unsafe code

Use of `unsafe` code is prohibited unless there is a unanonymous decision among
library maintainers on the exclusion from this rule. In such cases there is a
requirement to test unsafe code with sanitizers including Miri.


## Security

Security is the primary focus for this library; disclosure of security
vulnerabilities helps prevent user loss of funds. If you believe a vulnerability
may affect other implementations, please disclose this information according to
the [security guidelines](./SECURITY.md), work on which is currently in progress.
Before it is completed, feel free to send disclosure to Andrew Poelstra,
apoelstra@wpsoftware.net, encrypted with his public key, which may be found
at <https://www.wpsoftware.net/andrew/andrew.gpg>.


## Testing

Related to the security aspect, rust bitcoin developers take testing very
seriously. Due to the modular nature of the project, writing new test cases is
easy and good test coverage of the codebase is an important goal. Refactoring
the project to enable fine-grained unit testing is also an ongoing effort.

Fuzzing is heavily encouraged: feel free to add related material under `fuzz/`

Mutation testing is planned; any contribution there would be warmly welcomed.


## Going further

You may be interested in the guide by Jon Atack on
[How to review Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md)
and [How to make Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md).
While there are differences between the projects in terms of context and
maturity, many of the suggestions offered apply to this project.

Overall, have fun :)
