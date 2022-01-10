#!/bin/sh -ex

git rebase -x 'AS_DEPENDENCY=true TOOLCHAIN=stable ./contrib/test.sh' master &&
  PIN_VERSIONS=true AS_DEPENDENCY=true TOOLCHAIN="${BITCOIN_MSRV:-1.29.0}" ./contrib/test.sh &&
  AS_DEPENDENCY=true DO_FUZZ=true TOOLCHAIN=nightly ./contrib/test.sh
