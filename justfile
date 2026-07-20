alias ulf := update-lock-files

export RBMT_LOG_LEVEL := env("RBMT_LOG_LEVEL", "progress")

_default:
  @just --list

# Install necessary dev tools on system.
[group('system')]
@tools:
  cargo install --quiet --locked cargo-rbmt@$(grep "^rbmt.version" {{justfile_directory()}}/Cargo.toml | cut -d'"' -f2)

# Setup rbmt and run with given args.
@rbmt *args: tools
  cargo rbmt {{args}}

# Format workspace.
fmt: (rbmt "fmt")

# Lint everything.
lint: (rbmt "lint")

# Test everything.
test: (rbmt "test")

# Update the recent and minimal lock files.
update-lock-files: (rbmt "lock")
