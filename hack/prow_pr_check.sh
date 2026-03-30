#!/bin/bash

set -e

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

echo "Using git version $(git version)"
echo "Using go version $(go version)"

cd "${REPO_ROOT}"

# Run tests
make test

# Generate syncset and package resources
go run build/resources.go \
    -exclude debug-hook \
    -syncsetfile build/selectorsyncset.yaml

go run build/resources.go \
    -packagedir config/package

# Make sure nothing changed (i.e. generated resources being out of date)
if ! git diff --exit-code; then
    echo "FAILURE: unexpected changes after building. Run 'make syncset package' and commit changes."
    exit 1
fi
