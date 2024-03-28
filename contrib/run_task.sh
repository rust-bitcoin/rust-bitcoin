#!/usr/bin/env bash
#
# We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).
#
# ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration
#
# The minimal/recent manifests are handled by CI (rust.yaml).
#
# Jobs get run twice, once for each manifest:
#
# 1+2  stable
# 3+4  nightly
# 5+6  msrv
#
# Jobs get run once:
#
# 7   lint
# 8   docs
# 9   docsrs
# 10  bench
# 11  ASAN
# 12  WASM
# 13  Schemars
#
# Jobs run by CI (rust.yml but without this script):
#
# 14  Kani
# 15  Cross
# 16  Arch32bit
# 17  Embedded
#
# Jobs from other workflows:
#
# 18  coveralls.yml
# 19  release.yml
# 20  manage-pr.yml

set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
CRATES=("bitcoin" "hashes" "internals" "io" "units" "base58")

# Make all cargo invocations verbose.
export CARGO_TERM_VERBOSE=true

main() {
    local task="$1"

    check_required_commands

    cargo --version
    rustc --version
    /usr/bin/env bash --version
    locale
    env

    case $task in
        # 2 jobs each for these (one for each manifest).
	stable)
            build_and_test      # test + feature matrix
            ;;

	nightly)
            build_and_test
            ;;

	msrv)
            build_and_test
            ;;

        # 1 job each for these.
        lint)
            do_lint             # includes dup deps
            ;;

	docs)
            build_docs_with_stable_toolchain
	    ;;

	docsrs)
            build_docs_with_nightly_toolchain
	    ;;

	wasm)
	    do_wasm
	    ;;

	asan)
	    do_asan
	    ;;

	bench)
	    do_bench
	    ;;

	schemars)
	    do_schemars
	    ;;

        *)
            err "Error: unknown task $task"
            ;;
    esac
}

# Build and test for each crate, done with each toolchain.
build_and_test() {
    # Building the fuzz crate is more-or-less just a sanity check.
    pushd "$REPO_DIR/fuzz" > /dev/null
    cargo --locked build
    popd > /dev/null

    for crate in "${CRATES[@]}"; do
        pushd "$REPO_DIR/$crate" > /dev/null

        # Set crate specific variables.
        . contrib/test_vars.sh || exit 1

        do_test
        do_feature_matrix

        popd > /dev/null
    done
}

do_test() {
    # Use the current (recent/minimal) lock file.
    local cargo="cargo --locked"

    # Defaults / sanity checks
    $cargo build
    $cargo test

    # Split the EXAMPLES string into an array based on spaces.
    IFS=' ' read -r -a examples_array <<< "$EXAMPLES"

    for example in "${examples_array[@]}"; do
        # Extract name and features using parameter expansion.
        name="${example%%:*}"
        features="${example#*:}"
        $cargo run --example="$name" --features="$features"
    done

    if [ -e ./contrib/extra_tests.sh ];
    then
        ./contrib/extra_tests.sh
    fi
}

# Each crate defines its own feature matrix test so feature combinations
# can be better controlled.
do_feature_matrix() {
    local cargo="cargo --locked"

    $cargo build --no-default-features
    $cargo test --no-default-features

    # All crates have a "std" feature.
    loop_features "std" "$FEATURES_WITH_STD"

    # All but `bitcoin` crate have an "alloc" feature, this tests it
    # along with any other features that should work with "std".
    if [ -n "$FEATURES_WITHOUT_STD" ]
       then
           loop_features "" "$FEATURES_WITHOUT_STD"
    fi
}

# Build with each feature as well as all combinations of two features.
#
# Usage: loop_features "std" "this-feature that-feature other"
loop_features() {
    local use="$1"
    local features="$2"
    local cargo="cargo --locked"

    # All the provided features including $use
    $cargo build --no-default-features --features="$use $features"
    $cargo test --no-default-features --features="$use $features"

    read -r -a array <<< "$features"
    local len="${#array[@]}"

    if (( len > 1 )); then
        for ((i = 0 ; i < len ; i++ ));
        do
            $cargo build --features="$use ${array[i]}"
            $cargo test --features="$use ${array[i]}"

            if (( i < len - 1 )); then
               for ((j = i + 1 ; j < len ; j++ ));
               do
                   $cargo build --features="$use ${array[i]} ${array[j]}"
                   $cargo test --features="$use ${array[i]} ${array[j]}"
               done
            fi
        done
    fi
}

# Lint the workspace, lint the individual crate examples, check for duplicate dependencies.
do_lint() {
    need_nightly

    local cargo="cargo --locked"

    $cargo clippy --workspace --all-features --all-targets -- -D warnings

    for crate in "${CRATES[@]}"; do
        pushd "$REPO_DIR/$crate" > /dev/null

        # Set crate specific variables.
        . contrib/test_vars.sh || exit 1

        # Split the EXAMPLES string into an array based on spaces.
        IFS=' ' read -r -a examples_array <<< "$EXAMPLES"

        for example in "${examples_array[@]}"; do
            # Extract name and features using parameter expansion.
            name="${example%%:*}"
            features="${example#*:}"
            $cargo clippy --example "$name" --features="$features" -- -D warnings
        done
    done

    do_dup_deps
}

# We should not have any duplicate dependencies. This catches mistakes made upgrading dependencies
# in one crate and not in another (e.g. upgrade bitcoin_hashes in bitcoin but not in secp).
do_dup_deps() {
    # We can't use pipefail because these grep statements fail by design when there is no duplicate,
    # the shell therefore won't pick up mistakes in your pipe - you are on your own.
    set +o pipefail

    duplicate_dependencies=$(
        # Only show the actual duplicated deps, not their reverse tree, then
        # whitelist the 'syn' crate which is duplicated but it's not our fault.
        #
        # Temporarily allow 2 versions of `hashes`, `internals`, and `hex` while we upgrade.
        cargo tree  --target=all --all-features --duplicates \
            | grep '^[0-9A-Za-z]' \
            | grep -v 'syn' \
            | grep -v 'bitcoin_hashes' \
            | grep -v 'bitcoin-internals' \
            | grep -v 'hex-conservative' \
            | wc -l
                          )
    if [ "$duplicate_dependencies" -ne 0 ]; then
        echo "Dependency tree is broken, contains duplicates"
        cargo tree  --target=all --all-features --duplicates
        exit 1
    fi

    set -o pipefail
}

# Build the docs with a nightly toolchain, in unison with the function
# below this checks that we feature guarded docs imports correctly.
build_docs_with_nightly_toolchain() {
    need_nightly
    local cargo="cargo --locked"

    RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" $cargo doc --all-features
}

# Build the docs with a stable toolchain, in unison with the function
# above this checks that we feature guarded docs imports correctly.
build_docs_with_stable_toolchain() {
    local cargo="cargo +stable --locked"

    RUSTDOCFLAGS="-D warnings" $cargo doc --all-features
}

# Bench only works with a non-stable toolchain (nightly, beta).
do_bench() {
    for crate in bitcoin hashes; do
        pushd "$REPO_DIR/$crate" > /dev/null
        RUSTFLAGS='--cfg=bench' cargo bench
        popd > /dev/null
    done
}

# This is only relevant for hashes.
do_schemars() {
    pushd "$REPO_DIR/hashes/extended_tests/schemars" > /dev/null
    cargo test
    popd > /dev/null
}

do_wasm() {
    pushd "$REPO_DIR/hashes" > /dev/null

    clang --version &&
        CARGO_TARGET_DIR=wasm cargo install --force wasm-pack &&
        printf '\n' >> Cargo.toml &&
        printf '[target.wasm32-unknown-unknown.dev-dependencies]\n' >> Cargo.toml &&
        printf 'wasm-bindgen-test = "0.3"\n' >> Cargo.toml &&
        printf '\n' >> Cargo.toml &&
        printf '[lib]\n' >> Cargo.toml &&
        printf 'crate-type = ["cdylib", "rlib"]\n' >> Cargo.toml &&
        CC=clang-9 wasm-pack build &&
        CC=clang-9 wasm-pack test --node;

    popd > /dev/null
}

do_asan() {
    cargo clean
    CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
      RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
      ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
      cargo test --lib --no-default-features --features="${ASAN_FEATURES:-}" -Zbuild-std --target x86_64-unknown-linux-gnu
    # There is currently a bug in the MemorySanitizer (MSAN) - disable the job for now.
    #
    # cargo clean
    # CC='clang -fsanitize=memory -fno-omit-frame-pointer'                                         \
    #   RUSTFLAGS='-Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes'   \
    #   cargo test --lib --no-default-features --features="${ASAN_FEATURES:-}" -Zbuild-std --target x86_64-unknown-linux-gnu
}

# Check all the commands we use are present in the current environment.
check_required_commands() {
    need_cmd cargo
    need_cmd rustc
    need_cmd cut
    need_cmd grep
    need_cmd wc
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1
    then err "need '$1' (command not found)"
    fi
}

need_nightly() {
    cargo_ver=$(cargo --version)
    if echo "$cargo_ver" | grep -q -v nightly; then
        err "Need a nightly compiler; have $(cargo --version)"
    fi
}

err() {
    echo "$1" >&2
    exit 1
}

#
# Main script
#
main "$@"
exit 0
