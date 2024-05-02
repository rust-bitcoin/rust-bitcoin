# rust-bitcoin workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from `rust.yml` unless stated otherwise. Total 21 jobs but
`Prepare` is quick and must be run first anyway.

0.  `Prepare`
1.  `Stable - minimal`
2.  `Stable - recent`
3.  `Nightly - minimal`
4.  `Nightly - recent`
5.  `MSRV - minimal`
6.  `MSRV - recent`
7.  `Lint`
8.  `Docs`
9.  `Docsrs`
10. `Bench`
11. `ASAN`
12. `WASM`
13. `schemars`
14. `Arch32bit`
15. `Cross`
16. `Embedded`
17. `Kani`
18. `Coveralls` - run by `coveralls.yml`
19. `release` - run by `release.yml`
20. `labeler` - run by `manage-pr.yml`
