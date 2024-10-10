# Sourced by `rust-bitcoin-maintainer-tools/ci/run_task.sh`.
#
# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

REPO_DIR=$(git rev-parse --show-toplevel)

# Generates the crates list based on cargo workspace metadata.
function generate_crates_list() {
    cargo metadata --no-deps --format-version 1 | jq -j -r '.packages | map(.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr("'"$REPO_DIR"'/")) | join(" ")'
}

CRATES=$(generate_crates_list)
