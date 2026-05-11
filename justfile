alias ulf := update-lock-files

_default:
  @just --list

# Install necessary dev tools on system.
[group('system')]
tools:
  @{{justfile_directory()}}/contrib/ensure-maintainer-tools.sh

# Install workspace toolchains.
[group('system')]
@toolchains: tools
  RBMT_LOG_LEVEL=quiet cargo rbmt toolchains > /dev/null

# Setup rbmt and run with given args.
@rbmt *args: toolchains
  RBMT_LOG_LEVEL=quiet cargo rbmt {{args}}

# Format workspace.
@fmt: (rbmt "fmt")

# Check for API changes.
check-api: (rbmt "api")

# Lint everything.
lint: (rbmt "lint")

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
@update-lock-files: (rbmt "lock")
