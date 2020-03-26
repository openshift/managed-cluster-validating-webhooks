#!/bin/bash

# AppSRE team CD

set -exv

CURRENT_DIR=$(dirname "$0")

BASE_IMG="managed-cluster-validating-webhooks"
QUAY_IMAGE="quay.io/app-sre/${BASE_IMG}"
GIT_HASH=$(git rev-parse --short=7 HEAD)
IMAGETAG="${GIT_HASH}"

# build the image and the selectorsyncset
QUAY_USER="app-sre" IMAGETAG="$IMAGETAG" make render build-sss build-base

#push the image
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${QUAY_IMAGE}:${IMAGETAG}" \
    "docker://${QUAY_IMAGE}:latest"
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${QUAY_IMAGE}:${IMAGETAG}" \
    "docker://${QUAY_IMAGE}:${IMAGETAG}"

