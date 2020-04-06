#!/bin/bash

set -e

CURRENT_DIR=$(dirname "$0")

BASE_IMG="managed-cluster-validating-webhooks"
IMG="${BASE_IMG}:latest"

BUILD_CMD="build-base" IMG="$IMG" make lint test build-base
