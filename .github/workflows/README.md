# rust-bitcoin workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from rust.yml unless stated otherwise. Unfortunately we are now exceeding the 20 job target.
(Prepare is quick and must be run first anyway.)

1.  `Stable - minimal`
2.  `Stable - recent`
3.  `MSRV - minimal`
4.  `MSRV - recent`
5.  `Docs`
