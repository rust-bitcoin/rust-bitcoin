#!/usr/bin/env bash
#
# Script for querying the API.
#
# Shellcheck can't search dynamic paths
# shellcheck source=/dev/null

set -euo pipefail

file=""                         # File name of the all-features API text file.
crate_full_name=""              # Full crate name using underscores e.g., `bitcoin_primitives`.
crate=""                        # Short name e.g., `primitives`.

# Set to false to turn off verbose output.
flag_verbose=false

usage() {
    cat <<EOF
Usage:

    ./api.sh CRATE COMMAND

CRATE
  - hashes          bitcoin_hashes
  - io              bitcoin-io
  - primitives      bitcoin-primitives
  - units           bitcoin-units

CMD
  - types             Show all public types (structs and enums)
  - types_no_err      Show all public types (structs and enums) excluding error types.
EOF
}

main() {
    if [ "$#" -lt 1 ]; then
        usage
        exit 1
    fi

    local _crate="${1:---help}"
    if [[ "$_crate" == "-h" || "$_crate" == "--help" ]]; then
        usage
        exit 1
    fi

    if [ "$#" -lt 2 ]; then
        say_err "Missing COMMAND"
        usage
        exit 1
    fi

    local _cmd="$2"

    check_required_commands

    case $_crate in
        hashes)
            crate_full_name="bitcoin_hashes"
            ;;
        io)
            crate_full_name="bitcoin_io"
            ;;
        primitives)
            crate_full_name="bitcoin_primitives"
            ;;
        units)
            crate_full_name="bitcoin_units"
            ;;
        *)
            say_err "unsupported crate: $_crate"
            usage
            exit 1
    esac

    crate=$_crate
    file="./api/$crate/all-features.txt"

    verbose_say "Running command '$_cmd' on crate '$crate'"

    case $_cmd in
	types)
            structs_and_enums
            ;;

	types_no_err)
            structs_and_enums_no_err
            ;;

        traits)
            traits
            ;;

        *)
            err "Error: unknown cmd $_cmd"
            ;;
    esac
}

# Print all public structs and enums.
structs_and_enums() {
    grep -oP 'pub (struct|enum) \K[\w:]+(?=\(|;| |$)' "$file" | sed "s/^${crate_full_name}:://"
}

# Print all public structs and enums excluding error types.
structs_and_enums_no_err() {
    grep -oP 'pub (struct|enum) \K[\w:]+(?=\(|;| |$)' "$file" | sed "s/^${crate_full_name}:://" | grep -v Error
}

# Print all public traits.
traits() {
    grep -oP '^pub trait \K[\w:]+' "$file" | sed "s/^${crate_full_name}:://" | sed 's/:$//'
}

# Check all the commands we use are present in the current environment.
check_required_commands() {
    need_cmd grep
}

say() {
    echo "api: $1"
}

say_err() {
    say "$1" >&2
}

verbose_say() {
    if [ "$flag_verbose" = true ]; then
	say "$1"
    fi
}

err() {
    echo "$1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1
    then err "need '$1' (command not found)"
    fi
}

#
# Main script
#
main "$@"
exit 0
