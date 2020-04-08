#!/bin/bash

set -e

CURRENT_DIR=$(dirname "$0")

BUILD_CMD="build-base" make lint test build-base
