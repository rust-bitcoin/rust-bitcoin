# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# - hashes because of secp v0.30
# - io because of hashes
# - hex because 1.0 only has decoding
DUPLICATE_DEPS=("bitcoin_hashes" "hex-conservative" "bitcoin-io")
