set positional-arguments

# Once just v1.39.0 is widely deployed, simplify with the `read` function.
NIGHTLY_VERSION := trim(shell('cat "$1"', justfile_directory() / "nightly-version"))

alias ulf := update-lock-files

_default:
  @just --list

# Run the given CI task using maintainer tools.
@ci task toolchain="stable" lock="recent":
  {{justfile_directory()}}/contrib/ensure-maintainer-tools.sh
  cp -f {{justfile_directory()}}/Cargo-{{lock}}.lock {{justfile_directory()}}/Cargo.lock
  rustup run {{toolchain}} {{justfile_directory()}}/.maintainer-tools/ci/run_task.sh {{task}}

# Test workspace with stable toolchain.
test-stable: (ci "stable")

# Lint workspace.
lint: (ci "lint" NIGHTLY_VERSION)

# Generate documentation.
docs: (ci "docs")

# Generate documentation with nightly.
docsrs: (ci "docsrs" NIGHTLY_VERSION)

# Run benchmarks.
bench: (ci "bench")

# Sanity check given crates.
@check +crates:
  cargo test --quiet -p {{replace(crates, " ", " -p ")}} --no-default-features
  cargo test --quiet -p {{replace(crates, " ", " -p ")}} --all-features

# Format given crates.
@fmt +crates:
  cargo +{{NIGHTLY_VERSION}} fmt -p {{replace(crates, " ", " -p ")}}

# Check for API changes.
check-api:
 {{justfile_directory()}}/contrib/check-for-api-changes.sh

# Query the current API.
@query-api crate command:
 {{justfile_directory()}}/contrib/api.sh $1 $2

# Update the recent and minimal lock files.
update-lock-files:
 {{justfile_directory()}}/contrib/update-lock-files.sh

# Install githooks.
githooks-install:
 {{justfile_directory()}}/contrib/copy-githooks.sh

# Remove githooks.
githooks-remove:
 {{justfile_directory()}}/contrib/copy-githooks.sh -r

# Generate a dependency tree
gen-dep-tree:
        cargo tree --all-features --edges=no-dev,no-build --format={lib} --no-dedupe \
        --prune=serde_json --prune=rand --prune=bincode --prune=serde \
        -p bitcoin -p bitcoin-internals -p bitcoin_hashes@0.16.0 -p bitcoin-units \
        -p bitcoin-primitives -p chacha20-poly1305 -p base58ck -p bitcoin-addresses -p bitcoin-io@0.2.0 \
        -p bitcoin-consensus-encoding
