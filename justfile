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
  cargo +$(cat ./nightly-version) clippy --workspace --all-targets --all-features -- --deny warnings
  # lint warnings get inhibited unless we use `--nocapture`
  cargo test --quiet --workspace --doc -- --nocapture

# Run cargo fmt
fmt:
  cargo +$(cat ./nightly-version) fmt --all

# Check the formatting
format:
  cargo +$(cat ./nightly-version) fmt --all --check

# Generate documentation.
docsrs *flags:
  RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +$(cat ./nightly-version) doc --all-features {{flags}}

# Quick and dirty CI useful for pre-push checks.
sane: lint
  cargo test --quiet --workspace --all-targets --no-default-features > /dev/null || exit 1
  cargo test --quiet --workspace --all-targets > /dev/null || exit 1
  cargo test --quiet --workspace --all-targets --all-features > /dev/null || exit 1

  # Make an attempt to catch feature gate problems in doctests
  cargo test --manifest-path bitcoin/Cargo.toml --doc --no-default-features > /dev/null || exit 1

# Update the recent and minimal lock files.
update-lock-files:
  contrib/update-lock-files.sh

# Install githooks
githooks-install:
  ./contrib/copy-githooks.sh

# Remove githooks
githooks-remove:
  ./contrib/copy-githooks.sh -r
