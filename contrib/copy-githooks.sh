#!/usr/bin/env bash

set -euo pipefail

GIT_DIR=$(git rev-parse --git-common-dir)
HOOKS_DIR=$(git config --get core.hooksPath || echo "$GIT_DIR/hooks")

remove_githooks() {
	for hook in githooks/*
	do
		bn=$(basename "$hook")
		echo "Removing githook $bn"
		rm "$HOOKS_DIR/$bn"
	done
	exit 0
}

add_githooks() {
	mkdir -p "$HOOKS_DIR"
	cp -i githooks/* "$HOOKS_DIR"
	exit 0
}

while getopts "r" flag; do
	case $flag in
		r) remove_githooks
		;;
		*) exit 1
		;;
	esac
done

add_githooks # Copy githooks by default (no options provided)
