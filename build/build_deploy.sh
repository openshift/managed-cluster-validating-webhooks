#!/bin/bash

# AppSRE team CD

set -exv

# build the image, the selectorsyncset, and push the image
make -C $(dirname $0)/../ syncset build-base skopeo-push
