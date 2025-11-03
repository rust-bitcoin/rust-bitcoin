set positional-arguments

# Once just v1.39.0 is widely deployed, simplify with the `read` function.
NIGHTLY_VERSION := trim(shell('cat "$1"', justfile_directory() / "nightly-version"))

alias ulf := update-lock-files

_default:
  @just --list

# Run the given CI task using maintainer tools.
[group('ci')]
@ci task toolchain="stable" lock="recent":
  {{justfile_directory()}}/contrib/ensure-maintainer-tools.sh
  cp -f {{justfile_directory()}}/Cargo-{{lock}}.lock {{justfile_directory()}}/Cargo.lock
  rustup run {{toolchain}} {{justfile_directory()}}/.maintainer-tools/ci/run_task.sh {{task}}

# Test workspace with stable toolchain.
[group('ci')]
ci-stable: (ci "stable")

# Lint workspace.
[group('ci')]
ci-lint: (ci "lint" NIGHTLY_VERSION)

# Generate documentation.
[group('ci')]
ci-docs: (ci "docs")

# Generate documentation with nightly.
[group('ci')]
ci-docsrs: (ci "docsrs" NIGHTLY_VERSION)

# Run benchmarks.
[group('ci')]
ci-bench: (ci "bench")

# Quick workspace lint.
@lint:
  cargo +{{NIGHTLY_VERSION}} clippy --quiet --workspace --all-targets --all-features -- --deny warnings

# Quick workspace sanity check.
@sane: lint
  cargo test --quiet --workspace --all-targets --no-default-features
  cargo test --quiet --workspace --all-targets --all-features

# Format workspace.
@fmt:
  cargo +{{NIGHTLY_VERSION}} fmt --all

# Generate documentation (accepts cargo doc args, e.g. --open).
@docsrs *flags:
  RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +{{NIGHTLY_VERSION}} doc --all-features {{flags}}

# Check for API changes.
[group('scripts')]
check-api:
 {{justfile_directory()}}/contrib/check-for-api-changes.sh

# Query the current API.
[group('scripts')]
@query-api crate command:
 {{justfile_directory()}}/contrib/api.sh $1 $2

# Update the recent and minimal lock files.
[group('scripts')]
update-lock-files:
 {{justfile_directory()}}/contrib/update-lock-files.sh

# Install githooks.
[group('scripts')]
githooks-install:
 {{justfile_directory()}}/contrib/copy-githooks.sh

# Remove githooks.
[group('scripts')]
githooks-remove:
 {{justfile_directory()}}/contrib/copy-githooks.sh -r

# Generate a dependency tree for workspace crates.
[group('scripts')]
gen-dep-tree:
  {{justfile_directory()}}/contrib/gen-dep-tree.sh
