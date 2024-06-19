# rust-bitcoin workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from rust.yml unless stated otherwise. Unfortunately we are now exceeding the 20 job target.
(Prepare is quick and must be run first anyway.)

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
13. `Arch32bit`
14. `Cross`
15. `Embedded`
16. `Kani`
17. `Coveralls` - run by `coveralls.yml`
18. `release` - run by `release.yml`
19. `labeler` - run by `manage-pr.yml`
20. `Shellcheck` - run by `shellcheck.yml`
