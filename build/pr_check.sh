#!/bin/bash

set -e

echo "Using git version $(git version)"
echo "Using go version $(go version)"

CURRENT_DIR=$(dirname "$0")

#BUILD_CMD="build-base" make lint test build-sss build-base
make -C $(dirname $0)/../ test syncset build-base

# make sure nothing changed (i.e. SSS templates being invalid)
git diff --exit-code
MAKE_RC=$?

if [ "$MAKE_RC" != "0" ];
then
    echo "FAILURE: unexpected changes after building."
    exit $MAKE_RC
fi