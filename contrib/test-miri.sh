#!/usr/bin/env bash

set -euox pipefail

cd "$(dirname "$0")/.."

. contrib/test_vars.sh

target_features="$(rustc --print target-features | awk '{ if ($1 == "") { exit 0 } if (NR != 1 && $1 != "crt-static") { if (NR == 2) { printf "+%s", $1 } else { printf ",+%s", $1 } } }')"

for crate in $CRATES;
do
	# The secp256k1 crate cannot be miri-checked because of FFI, so we have to exclude it
	if cargo tree --manifest-path "$crate/Cargo.toml" | grep -q secp256k1;
	then
		echo "$crate depends on secp256k1, skipping..." >&2
		continue
	fi
	# Running miri is expensive and not needed for crates that don't contain unsafe
	if RUSTFLAGS="-C target-feature=$target_features -F unsafe-code" cargo check -q --all-features --target x86_64-unknown-linux-gnu 2>/dev/null;
	then
		echo "No unsafe code in $crate, skipping..." >&2
		continue
	fi

	RUSTFLAGS="-C target-feature=$target_features" RUSTDOCFLAGS="-C target-feature=$target_features" MIRIFLAGS=-Zmiri-backtrace=full cargo miri test --manifest-path "$crate/Cargo.toml" --all-features --target x86_64-unknown-linux-gnu
done
