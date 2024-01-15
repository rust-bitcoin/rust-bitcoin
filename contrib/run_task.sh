#!/bin/sh

set -ex

crate="$1"
task="$2"

export CARGO_TERM_VERBOSE=true

# Some tests require certain toolchain types.
NIGHTLY=false
STABLE=true
if cargo --version | grep nightly; then
    STABLE=false
    NIGHTLY=true
fi
if cargo --version | grep beta; then
    STABLE=false
fi

cd $crate
. contrib/test_vars.sh

case $task in
	test)
		cargo test --locked
		for example in $RUN_EXAMPLES; do
			example_name="`echo $example | cut -d ':' -f 1`"
			example_features="`echo $example | cut -d ':' -f 2`"
			cargo run --locked --example $example_name --features=$example_features
		done
		if [ -e ./contrib/extra_tests.sh ];
		then
			./contrib/extra_tests.sh
		fi
		;;
	lint)
		cargo clippy --locked --all-features --all-targets -- -D warnings
		for example in $LINT_EXAMPLES; do
			example_name="`echo $example | cut -d ':' -f 1`"
			example_features="`echo $example | cut -d ':' -f 2`"
			cargo clippy --locked --example $example_name --features=$example_features -- -D warnings
		done

		# We should not have any duplicate dependencies. This catches mistakes made upgrading dependencies
		# in one crate and not in another (e.g. upgrade bitcoin_hashes in bitcoin but not in secp).
		duplicate_dependencies=$(
			# Only show the actual duplicated deps, not their reverse tree, then
			# whitelist the 'syn' crate which is duplicated but it's not our fault.
			#
			# Whitelist `bitcoin_hashes` while we release it and until secp v0.28.0 comes out.
			cargo tree  --target=all --all-features --duplicates \
				| grep '^[0-9A-Za-z]' \
				| grep -v 'syn' \
				| wc -l
		)
		if [ "$duplicate_dependencies" -ne 0 ]; then
			echo "Dependency tree is broken, contains duplicates"
			cargo tree  --target=all --all-features --duplicates
			exit 1
		fi
		;;
	feature_matrix)
		cargo build --locked --no-default-features
		cargo test --locked --no-default-features

		cargo build --locked --no-default-features --features="$FEATURES"
		cargo test --locked --no-default-features --features="$FEATURES"

		for feature in ${FEATURES}; do
			cargo build --locked --no-default-features --features="$feature"
			cargo test --locked --no-default-features --features="$feature"

			# All combos of two features
			for featuretwo in `echo "${FEATURES}" | sed 's/^.*'\(^| \)$feature'\($| \)//'`; do
				cargo build --locked --no-default-features --features="$feature $featuretwo"
				cargo test --locked --no-default-features --features="$feature $featuretwo"
			done
		done
		;;
	fmt)
		cargo fmt --check
		;;
	docsrs)
		RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
		;;
	doc)
		RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features
		;;
	wasm)
		clang --version &&
		CARGO_TARGET_DIR=wasm cargo install --force wasm-pack &&
		printf '\n[target.wasm32-unknown-unknown.dev-dependencies]\nwasm-bindgen-test = "0.3"\n' >> Cargo.toml &&
		printf '\n[lib]\ncrate-type = ["cdylib", "rlib"]\n' >> Cargo.toml &&
		CC=clang-9 wasm-pack build &&
		CC=clang-9 wasm-pack test --node;
		;;
	asan)
		cargo clean
		CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
		RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
		ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
		cargo test --lib --no-default-features --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
		cargo clean
		CC='clang -fsanitize=memory -fno-omit-frame-pointer'                                         \
		RUSTFLAGS='-Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes'   \
		cargo test --lib --no-default-features --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
		;;
	bench)
		if [ "$STABLE" = true ]; then
			if [ -n "$RUSTUP_TOOLCHAIN" ]; then
				echo "RUSTUP_TOOLCHAIN is set to a stable toolchain but DO_BENCH requires a non-stable (beta, nightly) toolchain"
			else
				echo "DO_BENCH requires a non-stable (beta, nightly) toolchain"
			fi
			exit 1
		fi
		RUSTFLAGS='--cfg=bench' cargo bench
		;;
	*)
		echo "Error: unknown task $task" >&2
		exit 1
	;;
esac
