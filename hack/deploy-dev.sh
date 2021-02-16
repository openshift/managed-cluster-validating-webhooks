#!/bin/bash

# This script will break up the selectorsyncset in build/selectorsyncset.yaml
# and deploy all the objects to the currently logged in cluster
# for development purposes.
#
# example flow:
# $ export IMG=quay.io/my-user/managed-cluster-validating-webhooks IMAGETAG=latest IMAGE_TAG=latest
# $ make build-image
# $ make push-base
# $ make deploy-dev

set -euxo pipefail

OBJECTS_LENGTH=$(yq '.objects[0].spec.resources|length' < build/selectorsyncset.yaml)

for OBJECT in $(seq 0 $(("$OBJECTS_LENGTH"-1))); do
  oc apply -f <(yq ".objects[0].spec.resources[$OBJECT]" < build/selectorsyncset.yaml)
done
