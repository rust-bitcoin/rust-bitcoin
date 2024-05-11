#!/usr/bin/env bash
#
# Used by labeler.yaml
#
# Not to be confused with the per crate `test_vars.sh` used by
# `rust-bitcoin-maintainer-tools-run_task.sh`.
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

CRATES="$(cargo metadata --no-deps --format-version 1 | jq -j -r '.packages | map(.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr("'"$PWD"'/")) | join(" ")')"
DEPS="recent minimal"
