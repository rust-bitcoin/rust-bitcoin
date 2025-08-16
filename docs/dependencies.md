# Policy on adding dependencies 

TL;DR We are averse to adding dependencies, there needs to be a strong case for it.

Applies to any crate in the `rust-bitcoin` repository. When adding functionality one can add a
dependency or NIH it. When evaluating a dependency we consider:

* Maintainers are reputable and know idiomatic Rust well-enough
* Maintainers respond to bug reports quickly
* Idiomatic API, well documented, ideally stable or close to stable
* Conservative MSRV - hard requirement for mandatory dependencies
* Reasonable performance
* Good test coverage, CI, fuzzing, clippy, miri (if applicable)
* No reckless `unsafe` (see below).
* Maintainer responds well to code quality PRs (refactors)

These requirements apply recursively and the total dependency tree must not contain significantly
more code than what is required to implement the desired feature.

### Reckless unsafe 

Reckless `unsafe` is defined as having any of these properties: 

- Large complicated chunks of `unsafe` (whole module containing `unsafe` is an `unsafe` chunk!).
- (private) function not marked `unsafe` when it can UB depending on arguments (`actix-web` flamewar).
- Code that can be written without `unsafe` while staying equally fast thanks to compiler optimizations.
- Missing safe abstractions.

## Previously

In practice our dependency discussions have typically previously fallen into one of three camps:

* No, because the benefit is too niche/special-case.
* No, because of MSRV policy or past MSRV arguments.
* A nuanced discussion where we have our own unsafe code and wonder whether we should outsource the
  responsibility or not (e.g. `ArrayVec`) (written policy is also not much guide because it's really
  only maintainers who have arguments like this anyway)
