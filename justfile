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
  cargo clippy --workspace --all-targets --all-features -- --deny warnings

# Check the formatting
format:
  cargo +nightly fmt --all --check
