#!/bin/sh

set -ex

if [ -n "$1" ];
then
	deps="$1"
else
	deps="minimal recent"
fi

CRATES="bitcoin hashes hex internals"

for dep in $deps
do
	cp Cargo-$dep.lock Cargo.lock
	for crate in ${CRATES}
	do
	    (
		cd "$crate"
		./contrib/test.sh
	    )
	done
	if [ $dep = recent ];
	then
		# We always test committed dependencies but we want to warn if they could've been updated
		cargo update
		if diff Cargo-recent.lock Cargo.lock;
		then
			echo Dependencies are up to date
		else
			echo "::warning file=Cargo-recent.lock::Dependencies could be updated"
		fi
	fi
done

exit 0
