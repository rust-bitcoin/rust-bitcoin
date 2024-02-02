#!/usr/bin/env bash

CRATES="`cargo metadata --no-deps --format-version 1 | jq -j -r '.packages | map(.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr("'$PWD'/")) | join(" ")'`"
DEPS="recent minimal"
