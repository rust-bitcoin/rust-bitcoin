set positional-arguments

NIGHTLY_VERSION := `cat nightly-version`

alias ulf := update-lock-files

default:
  @just --list

# Run the given CI task using maintainer tools.
@ci task toolchain="stable" lock="recent":
  {{justfile_directory()}}/contrib/ensure-maintainer-tools.sh
  cp -f {{justfile_directory()}}/Cargo-{{lock}}.lock {{justfile_directory()}}/Cargo.lock
  rustup run {{toolchain}} {{justfile_directory()}}/.maintainer-tools/ci/run_task.sh {{task}}

# Test with stable toolchain.
test-stable: (ci "stable")

# Test with nightly toolchain.
test-nightly: (ci "nightly")

# Test with MSRV toolchain.
test-msrv: (ci "msrv")

# Lint workspace.
lint: (ci "lint" NIGHTLY_VERSION)

# Generate documentation.
docs: (ci "docs")

# Generate documentation with nightly.
docsrs: (ci "docsrs" NIGHTLY_VERSION)

# Run benchmarks.
bench: (ci "bench")

# Cargo build everything.
build:
  cargo build --workspace --all-targets --all-features

# Cargo check everything.
check:
  cargo check --workspace --all-targets --all-features

# Run cargo fmt
fmt:
  cargo +$(cat ./nightly-version) fmt --all

# Check the formatting
format:
  cargo +$(cat ./nightly-version) fmt --all --check

# Quick and dirty CI useful for pre-push checks.
sane: lint
  cargo test --quiet --workspace --all-targets --no-default-features > /dev/null || exit 1
  cargo test --quiet --workspace --all-targets > /dev/null || exit 1
  cargo test --quiet --workspace --all-targets --all-features > /dev/null || exit 1

  # Make an attempt to catch feature gate problems in doctests
  cargo test --manifest-path bitcoin/Cargo.toml --doc --no-default-features > /dev/null || exit 1

# Check for API changes.
check-api:
 contrib/check-for-api-changes.sh

# Query the current API.
@query-api crate command:
 contrib/api.sh $1 $2

# Update the recent and minimal lock files.
update-lock-files:
  contrib/update-lock-files.sh

# Install githooks
githooks-install:
  ./contrib/copy-githooks.sh

# Remove githooks
githooks-remove:
  ./contrib/copy-githooks.sh -r

# Generate a dependency tree
gen-dep-tree:
        cargo tree --all-features --edges=no-dev,no-build --format={lib} --no-dedupe \
        --prune=serde_json --prune=rand --prune=bincode --prune=serde \
        -p bitcoin -p bitcoin-internals -p bitcoin_hashes@0.16.0 -p bitcoin-units \
        -p bitcoin-primitives -p chacha20-poly1305 -p base58ck -p bitcoin-addresses -p bitcoin-io@0.2.0 \
        -p bitcoin-consensus-encoding
