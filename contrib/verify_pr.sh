#!/usr/bin/env bash

# verify_pr.sh
# A script to run all checks required for a Pull Request to rust-bitcoin
# Usage: ./contrib/verify_pr.sh

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Starting PR Verification ===${NC}"

# 1. Get Nightly Version from file
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

NIGHTLY_FILE="$REPO_ROOT/nightly-version"
if [ -f "$NIGHTLY_FILE" ]; then
    NIGHTLY_VERSION=$(cat "$NIGHTLY_FILE" | tr -d '[:space:]')
    echo -e "Required Nightly Version: ${GREEN}$NIGHTLY_VERSION${NC}"
else
    echo -e "${RED}Error: nightly-version file not found!${NC}"
    exit 1
fi

# 2. Check if toolchain is installed
if ! rustup toolchain list | grep -q "$NIGHTLY_VERSION"; then
    echo -e "${YELLOW}Toolchain $NIGHTLY_VERSION not found. Installing...${NC}"
    rustup install "$NIGHTLY_VERSION"
    rustup component add rustfmt clippy --toolchain "$NIGHTLY_VERSION"
else
    echo -e "Toolchain $NIGHTLY_VERSION found."
fi

# 3. Format Check
echo -e "\n${YELLOW}=== 1. Checking Formatting ===${NC}"
if cargo +$NIGHTLY_VERSION fmt --all -- --check; then
    echo -e "${GREEN}Formatting passed.${NC}"
else
    echo -e "${RED}Formatting failed.${NC}"
    echo -e "Running formatter to fix issues..."
    cargo +$NIGHTLY_VERSION fmt --all
    echo -e "${YELLOW}Formatting fixed. Please verify the changes.${NC}"
fi

# 4. Lint (Clippy)
echo -e "\n${YELLOW}=== 2. Running Lints (Clippy) ===${NC}"
cargo +$NIGHTLY_VERSION clippy --quiet --workspace --all-targets --all-features -- --deny warnings
echo -e "${GREEN}Lints passed.${NC}"

# 5. Tests (No Default Features)
echo -e "\n${YELLOW}=== 3. Running Tests (No Default Features) ===${NC}"
cargo test --quiet --workspace --all-targets --no-default-features
echo -e "${GREEN}No-default-features tests passed.${NC}"

# 6. Tests (All Features)
echo -e "\n${YELLOW}=== 4. Running Tests (All Features) ===${NC}"
cargo test --quiet --workspace --all-targets --all-features
echo -e "${GREEN}All-features tests passed.${NC}"

# 7. Documentation
echo -e "\n${YELLOW}=== 5. Building Documentation ===${NC}"
export RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links"
cargo +$NIGHTLY_VERSION doc --no-deps --all-features
echo -e "${GREEN}Documentation build passed.${NC}"

echo -e "\n${GREEN}=== Verification Complete! ===${NC}"
echo -e "Your code is ready for a Pull Request."
