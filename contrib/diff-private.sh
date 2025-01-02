#!/usr/bin/env bash
#
# Script for diffing files in `private` module.
#
# We use `internals/src/private` as a SSOT and then copy it to various
# other crates. This script checks that no one patched the copies.
#
# Shellcheck can't search dynamic paths
# shellcheck source=/dev/null
#
# I couldn't get rid of this warning and still have the script work.
# shellcheck disable=SC2181

# Don't set -e because we want to check all the crates at once not
# error for the first difference.
set -uo pipefail

# Set to false to turn off verbose output.
flag_verbose=false

main() {
    check_required_commands
    set_globals
    local retval=0

    for crate in $CRATES; do
        # `internals` crate holds the SSOT. 
        if [[ "$crate" == "internals" ]]; then
            continue
        fi

        # Only check crates that have a `private` directory.
        if [[ ! -d "$crate/src/private" ]]; then
            continue
        fi

        diff_files "$crate"
        different=$?
        if [[ $different -ne 0 ]]; then
            retval=$different
        fi
    done

    exit $retval
}

set_globals() {
    REPO_DIR=$(git rev-parse --show-toplevel)
    CRATES=$(generate_crates_list)
    # The single source of truth for files in `private/`.
    SSOT="$REPO_DIR/internals/src/private"
}

# Diff all the files in `SSOT` against those in `$crate`.
diff_files() {
    local crate=$1
    local retval=0

    # Sanity check.
    if [[ ! -d "$SSOT" ]]; then
        echo "SSOT directory do not exist: $SSOT"
        exit 1
    fi

    verbose_say "diff'ing files in SSOT against $crate"

    for file_ssot in "$SSOT"/*; do
        if [[ -f "$file_ssot" ]]; then
            filename=$(basename "$file_ssot")
            if [[ "$filename" == "mod.rs" ]]; then
                continue
            fi

            file_copy="$REPO_DIR/$crate/src/private/$filename"
            if [[ -f "$file_copy" ]]; then
                diff "$file_ssot" "$file_copy"
                if [[ $? -eq 0 ]]; then
                    verbose_say "✅ File $crate/src/private/$filename is identical to file in SSOT."
                else
                    say_err "❌ File $crate/src/private/$filename differs from version in SSOT."
                    retval=1
                fi
            else
                say_err "⚠️ File $filename exists in $SSOT but not in $crate/src/private."
                retval=2
            fi
        fi
    done

    # There should be no additional files in the copied directories.
    for file_copy in "$crate"/private/src/*; do
        if [[ -f "$file_copy" ]]; then
            filename=$(basename "$file_copy")
            file_ssot="$SSOT/$filename"
            if [[ ! -f "$file_ssot" ]]; then
                say_err "⚠️ File $filename exists in $crate but not in $SSOT."
                retval=3
            fi
        fi
    done

    return $retval
}

# Generates the crates list based on cargo workspace metadata.
generate_crates_list() {
    cargo metadata --no-deps --format-version 1 | jq -j -r '.packages | map(.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr("'"$REPO_DIR"'/")) | join(" ")'
}

# Check all the commands we use are present in the current environment.
check_required_commands() {
    need_cmd grep
    need_cmd cargo
    need_cmd git
}

say() {
    echo "diff-private: $1"
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

