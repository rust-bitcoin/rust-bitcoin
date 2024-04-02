default:
  @just --list

# Cargo build everything.
build:
  cargo build --workspace --all-targets --all-features

# Cargo check everything.
check:
  cargo check --workspace --all-targets --all-features

# Lint everything.
lint:
  cargo +$(cat .github/nightly-version) clippy --workspace --all-targets --all-features -- --deny warnings

# Check the formatting
format:
  cargo +$(cat .github/nightly-version) fmt --all --check

# Quick and dirty CI useful for pre-push checks.
sane: lint
  cargo test --quiet --workspace --all-targets --no-default-features > /dev/null || exit 1
  cargo test --quiet --workspace --all-targets > /dev/null || exit 1
  cargo test --quiet --workspace --all-targets --all-features > /dev/null || exit 1

  # doctests don't get run from workspace root with `cargo test`.
  cargo test --quiet --workspace --doc || exit 1

  # Make an attempt to catch feature gate problems in doctests
  cargo test --manifest-path bitcoin/Cargo.toml --doc --no-default-features > /dev/null || exit 1

# Update the recent and minimal lock files.
update-lock-files:
  contrib/update-lock-files.sh
