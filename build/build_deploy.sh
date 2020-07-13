#!/bin/bash

# AppSRE team CD

set -exv

# build the image, the selectorsyncset, and push the image
make -C $(dirname $0)/../ IMAGETAG="$IMAGETAG" syncset build-base skopeo-push
