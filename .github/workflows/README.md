# rust-bitcoin workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from rust.yml unless stated otherwise. Unfortunately we are now exceeding the 20 job target.
(Prepare is quick and must be run first anyway.)

0.  `Test - stable toolchain, minimal deps`
1.  `Test - stable toolchain, recent deps`
2.  `Test - msrv toolchain, minimal deps`
3.  `Test - msrv toolchain, recent deps`
4.  `Check (lint)`
5.  `Check (docs)`
6.  `Check (docsrs)`
7.  `Check (bench)`
8.  `Prepare`
9.  `Test 32-bit version`
10. `Cross test`
11. `WASM`
12. `Kani`
13. `Embedded`
14. `ASAN`
15. `Coveralls` - run by `coveralls.yml`
16. `release` - run by `gh-release.yml`
17. `labeler` - run by `manage-pr.yml`
