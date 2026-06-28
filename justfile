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

# Update the recent and minimal lock files.
@update-lock-files: (rbmt "lock")
