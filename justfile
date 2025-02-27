set positional-arguments

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

# Generate documentation.
docsrs *flags:
  RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +$(cat ./nightly-version) doc --all-features {{flags}}

# Update the recent and minimal lock files.
update-lock-files:
  contrib/update-lock-files.sh
