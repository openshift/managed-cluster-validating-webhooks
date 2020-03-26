#!/bin/bash

# AppSRE team CD

set -exv

# build the image, the selectorsyncset, and push the imate
IMAGETAG="$IMAGETAG" make render build-sss build-base skopeo-push

