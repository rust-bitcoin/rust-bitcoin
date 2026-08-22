#!/usr/bin/env bash

# Manage the shared fuzz corpora stored in the qa-assets repository.
#
# Usage: corpora.sh {seed QA_DIR TARGET | refresh INCOMING_DIR TARGETS_FILE | push}
#
# Commands:
#   seed     Copy a target's stored corpus into fuzz/corpus.
#   refresh  Replace each stored corpus with the one under INCOMING_DIR and drop
#            targets not listed in TARGETS_FILE.
#   push     CI only, not meant to be run locally. Commit and push to
#            qa-assets. Reads QA_ASSETS_PUSH_TOKEN, SOURCE, RUN_URL and
#            BRANCH from the environment.

set -euo pipefail

usage="Usage: $0 {seed QA_DIR TARGET | refresh INCOMING_DIR TARGETS_FILE | push}"

seed() {
  local qa="${1:?$usage}" target="${2:?$usage}"
  local corpus
  corpus="$(dirname "$0")/corpus/$target"
  mkdir -p "$corpus"
  if [ -d "$qa/fuzz_corpora/$target" ]; then
    find "$qa/fuzz_corpora/$target" -maxdepth 1 -type f -exec cp -t "$corpus/" {} +
  fi
}

refresh() {
  local incoming="${1:?$usage}" targets_file="${2:?$usage}"
  local dir name
  mkdir -p fuzz_corpora "$incoming"
  for dir in "$incoming"/corpus-*/; do
    [ -d "$dir" ] || continue # skip on empty corpora, string expansion yields literal pattern
    name=$(basename "$dir")
    name=${name#corpus-}
    rm -rf "fuzz_corpora/$name"
    mkdir -p "fuzz_corpora/$name"
    find "$dir" -maxdepth 1 -type f -exec cp -t "fuzz_corpora/$name/" {} +
  done
  for dir in fuzz_corpora/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    grep -qx "$name" "$targets_file" || rm -rf "$dir" # drop targets that no longer exist upstream
  done
}

push() {
  git add -A fuzz_corpora
  if git diff --cached --quiet; then
    echo "No corpus changes"
    exit 0
  fi
  if [ -z "${QA_ASSETS_PUSH_TOKEN:-}" ]; then
    echo "::error::QA_ASSETS_PUSH_TOKEN is not set, refusing to drop the corpus updates"
    exit 1
  fi
  git config user.name "github-actions[bot]"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  git commit -m "Update fuzz corpora" \
    -m "Source: $SOURCE" \
    -m "Run: $RUN_URL"
  # try to push three times, rebasing on the remote branch if we race with it
  for _ in 1 2 3; do
    git push origin "HEAD:$BRANCH" && exit 0
    git pull --rebase origin "$BRANCH"
  done
  exit 1
}

export LC_ALL=C
cmd="${1:?$usage}"
shift
case "$cmd" in
  seed | refresh | push) "$cmd" "$@" ;;
  *)
    echo "$usage" >&2
    exit 2
    ;;
esac
