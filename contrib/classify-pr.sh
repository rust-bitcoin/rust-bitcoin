#!/bin/sh

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <tip of master> <tip of PR>"
  exit 1
fi

pr_tip=$1
master_tip=$2

# When called on `pull_request`, GA fails to pull down master by default.
# When called on `push`, GA fails to pull down the PR by default, only its merge commit.
# The simplest way to deal with this is to just pull both explicitly.
git fetch origin "$master_tip":master_tip
git fetch origin "$pr_tip":pr_tip

pr_base=$(git merge-base master_tip pr_tip)

echo "Using  master $master_tip"
echo "Using  PR tip $pr_tip"
echo "Using PR base $pr_base"

# If something modifies any non-markdown file, it's considered a source code change.
if git diff --name-only "$pr_base" "$pr_tip" | grep -qv "^.md$"; then
    echo "pr_changed_source=true" >> "$GITHUB_OUTPUT"
else
    echo "pr_changed_source=false" >> "$GITHUB_OUTPUT"
fi

