#!/bin/bash

set -e

CURRENT_DIR=$(dirname "$0")

BASE_IMG="managed-cluster-validating-webhooks"
IMG="${BASE_IMG}:latest"

BUILD_CMD="docker build" IMG="$IMG" make docker-build
