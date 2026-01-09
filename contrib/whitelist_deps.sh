# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# - hashes because of secp v0.30
# - io because of hashes
# - hex because 1.0 only has decoding
# - libc v0.2.159 appears twice (runtime vs build-dependency) but is the same version, so Cargo deduplicates correctly
DUPLICATE_DEPS=("bitcoin_hashes" "hex-conservative" "bitcoin-io" "libc")
