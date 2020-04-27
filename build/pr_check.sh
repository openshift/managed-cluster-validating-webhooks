#!/bin/bash

set -e

CURRENT_DIR=$(dirname "$0")

BUILD_CMD="build-base" make lint test build-sss build-base

# make sure nothing changed (i.e. SSS templates being invalid)
git diff --exit-code
MAKE_RC=$?

if [ "$MAKE_RC" != "0" ];
then
    echo "FAILURE: unexpected changes after building.  Check that:"
    echo " - files in templates/ dir end in '.tmpl'"
    echo " - you have run make build-sss and committed the changes"
    exit $MAKE_RC
fi