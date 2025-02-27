# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
#
# Used by labeler.yaml
#
# Not to be confused with the per crate `test_vars.sh` used by
# `rust-bitcoin-maintainer-tools-run_task.sh`.
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

CRATES="units"
DEPS="recent minimal"
