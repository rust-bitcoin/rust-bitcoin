#!/usr/bin/env bash

. contrib/test_vars.sh

crates="`cargo metadata --no-deps --format-version 1 | jq -c '.packages | map(.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr("'$PWD'/"))'`"
deps="`echo -n $DEPS | jq -R -c 'split(" ")'`"
# debug
echo "$crates"
echo "$deps"

echo "crates=$crates" >> $GITHUB_OUTPUT
echo "deps=$deps" >> $GITHUB_OUTPUT
