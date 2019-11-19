#!/bin/bash

# AppSRE team CD

set -exv

CURRENT_DIR=$(dirname "$0")

BASE_IMG="managed-cluster-validating-webhooks"
QUAY_IMAGE="quay.io/app-sre/${BASE_IMG}"
IMG="${BASE_IMG}:${VERSION_MAJOR}.${VERSION_MINOR}-${GIT_HASH}"
VERSION_MAJOR=0
VERSION_MINOR=1
SELECTOR_SYNC_SET_TEMPLATE_DIR=templates
YAML_DIRECTORY=deploy
SELECTOR_SYNC_SET_DESTINATION=templates/00-osd-managed-cluster-validating-webhooks.selectorsyncset.yaml.tmpl
REPO_NAME=managed-cluster-validating-webhooks
GIT_HASH=$(git rev-parse --short=7 HEAD)

# build the image
BUILD_CMD="docker build" IMG="$IMG" make docker-build

GEN_SYNCSET=$(generate_syncset.py -t "${SELECTOR_SYNC_SET_TEMPLATE_DIR}" -y "${YAML_DIRECTORY}" -d "${SELECTOR_SYNC_SET_DESTINATION}" -r "${REPO_NAME}")

# push the image
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${IMG}" \
    "docker://${QUAY_IMAGE}:latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:${IMG}" \
    "docker://${QUAY_IMAGE}:${GIT_HASH}"

