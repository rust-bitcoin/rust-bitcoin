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
- at least two "accepts"/ACKs from the repository maintainers
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


## Coding conventions

Library reflects Bitcoin Core approach whenever possible.

### Formatting

The repository currently uses `rustfmt` (WIP, some directories are excluded). We use nightly
features so to run the formatter use `cargo +nightly fmt`. (Remember that your editor may be
configured to fmt with a stable toolchain, this will result in many unwanted changes.)

### Naming conventions

Naming of data structures/enums and their fields/variants must follow names used
in Bitcoin Core, with the following exceptions:
- the case should follow Rust standards (i.e. PascalCase for types and
  snake_case for fields and variants);
- omit `C`-prefixes.

### Unsafe code

Use of `unsafe` code is prohibited unless there is a unanimous decision among
library maintainers on the exclusion from this rule. In such cases there is a
requirement to test unsafe code with sanitizers including Miri.


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
the [readme](./REAME.md) for more information.


## Going further

You may be interested in the guide by Jon Atack on
[How to review Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md)
and [How to make Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md).
While there are differences between the projects in terms of context and
maturity, many of the suggestions offered apply to this project.

Overall, have fun :)
