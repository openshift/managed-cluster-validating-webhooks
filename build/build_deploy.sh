#!/bin/bash

# AppSRE team CD

set -exv

# build the image, the selectorsyncset, and push the imate
QUAY_USER="app-sre" IMAGETAG="$IMAGETAG" make render build-sss build-base skopeo-push

