# No shebang, this file should not be executed.
# shellcheck disable=SC2148

cargo clippy --all-targets --no-default-features --keep-going -- -D warnings
