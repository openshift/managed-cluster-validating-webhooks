#!/bin/bash

# AppSRE team CD

set -exv

CURRENT_DIR=$(dirname "$0")

BASE_IMG="managed-cluster-validating-webhooks"
QUAY_IMAGE="quay.io/app-sre/${BASE_IMG}"
VERSION_MAJOR=0
VERSION_MINOR=1
SELECTOR_SYNC_SET_TEMPLATE_DIR=templates
BUILD_DIRECTORY=build
SELECTOR_SYNC_SET_DESTINATION=deploy/selectorsyncset.yaml
REPO_NAME=managed-cluster-validating-webhooks
GIT_HASH=$(git rev-parse --short=7 HEAD)
IMAGETAG="${VERSION_MAJOR}.${VERSION_MINOR}-${GIT_HASH}"
IMG="$QUAY_IMAGE":"$IMAGETAG"

# build the image and the selectorsyncset

docker run --rm -v `pwd -P`:`pwd -P` python:2.7.15 /bin/sh -c "cd `pwd`; pip install oyaml; python build/generate_syncset.py -t ${SELECTOR_SYNC_SET_TEMPLATE_DIR} -b ${BUILD_DIRECTORY} -d ${SELECTOR_SYNC_SET_DESTINATION} -r ${REPO_NAME}"

IMG="$QUAY_IMAGE" IMAGETAG="$IMAGETAG" make build-base
#push the image
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${QUAY_IMG}:${IMAGETAG}" \
    "docker://${QUAY_IMAGE}:latest"
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${QUAY_IMG}:${IMAGETAG}" \
    "docker://${QUAY_IMAGE}:${IMAGETAG}"
