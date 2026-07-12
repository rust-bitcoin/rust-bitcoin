#!/usr/bin/env bash
#
# Checks semver compatibility and non-additive cargo features.
#
# Usage: check-semver.sh [BASELINE_COMMIT]
#   BASELINE_COMMIT: Git commit hash to compare against (defaults to master)

set -euo pipefail

BASELINE_COMMIT="${1:-$(git rev-parse master)}"

# Check for required tools.
if ! command -v jq &> /dev/null; then
    echo "ERROR: jq is required but not installed"
    exit 1
fi

declare -A CRATE_VARIANTS=(
    [bitcoin]="all-features no-default-features"
    [base58ck]="all-features no-default-features"
    [bitcoin_hashes]="all-features no-default-features alloc"
    [bitcoin-units]="all-features no-default-features alloc"
    [bitcoin-io]="all-features no-default-features alloc"
    [bitcoin-consensus-encoding]="all-features no-default-features alloc"
)

# Crates that have reached 1.0 must not introduce semver-breaking API changes.
SEMVER_HARD_FAIL_CRATES=("bitcoin-consensus-encoding")

WORKSPACE_ROOT="$(git rev-parse --show-toplevel)"

# Get all feature names for a package name except `default` (workspace members only).
get_crate_features() {
    local pkg_name="$1"
    # Filter on pkgid to ensure only workspace members are considered.
    cargo metadata --format-version 1 | \
        jq -r ".packages[] | select(.name == \"$pkg_name\" and (.id | startswith(\"path+file://\"))) | .features | keys[] | select(. != \"default\")" | sort | uniq
}

main() {
    check_non_additive_features
    check_semver_breaks
}

check_non_additive_features() {
    echo "Checking for non-additive features..."

    local has_non_additive=false

    for pkg_name in "${!CRATE_VARIANTS[@]}"; do
        echo "Checking $pkg_name for non-additive features..."
        local current_features=""
        for feature in $(get_crate_features "$pkg_name"); do
            current_features="$current_features --current-features $feature"
        done

        # Compare no-features to all-features.
        if ! cargo semver-checks \
            -p "$pkg_name" \
            --release-type minor \
            --only-explicit-features \
            --baseline-root "$WORKSPACE_ROOT" \
            --baseline-features "" \
            $current_features; then
            echo "Non-additive cargo features found in $pkg_name"
            has_non_additive=true
        fi
    done

    if [ "$has_non_additive" = true ]; then
        echo "ERROR: Non-additive cargo features detected"
        exit 1
    fi

    echo "No non-additive cargo features found"
}

check_semver_breaks() {
    echo "Checking semver against baseline: $BASELINE_COMMIT"

    local has_hard_fails=false

    for pkg_name in "${!CRATE_VARIANTS[@]}"; do
        for variant in ${CRATE_VARIANTS[$pkg_name]}; do
            echo "Checking $pkg_name ($variant)..."

            local features_args=""
            case "$variant" in
                all-features)
                    features_args="--all-features"
                    ;;
                no-default-features)
                    features_args="--only-explicit-features"
                    ;;
                alloc)
                    features_args="--only-explicit-features --current-features alloc"
                    ;;
            esac

            if ! cargo semver-checks \
                -p "$pkg_name" \
                --release-type minor \
                --baseline-rev "$BASELINE_COMMIT" \
                $features_args; then
                echo "Breaking changes found in $pkg_name ($variant)"
                touch semver-break

                for hard_fail_crate in "${SEMVER_HARD_FAIL_CRATES[@]}"; do
                    if [[ "$pkg_name" == "$hard_fail_crate" ]]; then
                        has_hard_fails=true
                    fi
                done
            fi
        done
    done

    if [ "$has_hard_fails" = true ]; then
        echo "Semver break detected in a 1.0 crate; failing CI"
        exit 1
    fi
}

#
# Main script
#
main "$@"
exit 0
