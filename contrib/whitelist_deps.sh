# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# - hashes because of secp v0.30
# - io because of hashes
# - hex because 1.0 only has decoding
# - The following because of old bitcoin dep in fuzz:
#  - base58ck
#  - bitcoin
#  - internals
#  - units
#  - secp256k1
#  - secp256k1-sys
DUPLICATE_DEPS=(
    "bitcoin_hashes"
    "bitcoin-io"
    "hex-conservative"
    "base58ck"
    "bitcoin\ v"
    "bitcoin-internals"
    "bitcoin-units"
    "secp256k1\ v"
    "secp256k1-sys"
)
