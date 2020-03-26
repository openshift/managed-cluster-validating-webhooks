SHELL := /usr/bin/env bash

TEMPLATEFILES := $(shell find ./templates -type f -name "*.yaml.tmpl")

BASE_IMG="managed-cluster-validating-webhooks"
NAMESPACE ?= openshift-validation-webhook
SVCNAME ?= validation-webhook
SANAME ?= validation-webhook
GIT_HASH=$(shell git rev-parse --short=7 HEAD)
IMAGETAG="${GIT_HASH}"
CABUNDLECONFIGMAP ?= webhook-cert
VWC_ANNOTATION ?= managed.openshift.io/inject-cabundle-from
QUAY_USER ?= app-sre

IMG ?= quay.io/${QUAY_USER}/${BASE_IMG}


SELECTOR_SYNC_SET_TEMPLATE_DIR=deploy
BUILD_DIRECTORY=build
SELECTOR_SYNC_SET_DESTINATION=build/selectorsyncset.yaml
REPO_NAME ?= managed-cluster-validating-webhooks

CONTAINER_ENGINE?=docker

default: all
all: build-base build-sss

.PHONY: build-sss
build-sss: render
	${CONTAINER_ENGINE} run --rm -v `pwd -P`:`pwd -P` python:2.7.15 /bin/sh -c "cd `pwd`; pip install oyaml; python build/generate_syncset.py -t ${SELECTOR_SYNC_SET_TEMPLATE_DIR} -b ${BUILD_DIRECTORY} -d ${SELECTOR_SYNC_SET_DESTINATION} -r ${REPO_NAME}"


.PHONY: build-base
build-base: build/Dockerfile
	$(CONTAINER_ENGINE) build -t $(IMG):$(IMAGETAG) -f build/Dockerfile . 

.PHONY: push-base
push-base: build/Dockerfile
	$(CONTAINER_ENGINE) push $(IMG):$(IMAGETAG)

.PHONY: skopeo-push
skopeo-push:
	skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
		"docker-daemon:${IMG}:${IMAGETAG}" \
		"docker://${IMG}:latest"
	skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
		"docker-daemon:${IMG}:${IMAGETAG}" \
		"docker://${IMG}:${IMAGETAG}"


# TODO: Change the render to allow for the permissions to have a list of all the webhook names
# TODO: Pull that list of names from the yaml files?
render: $(TEMPLATEFILES) build/Dockerfile
	for f in $(TEMPLATEFILES); do \
		sed \
			-e "s!\#NAMESPACE\#!$(NAMESPACE)!g" \
			-e "s!\#SVCNAME\#!$(SVCNAME)!g" \
			-e "s!\#SANAME\#!$(SANAME)!g" \
			-e "s!\#IMAGETAG\#!$(IMAGETAG)!g" \
			-e "s!\#IMG\#!$(IMG)!g" \
			-e "s!\#CABUNDLECONFIGMAP\#!$(CABUNDLECONFIGMAP)!g" \
			-e "s!\#VWC_ANNOTATION\#!$(VWC_ANNOTATION)!g" \
		$$f > deploy/$$(basename $$f .tmpl) ;\
	done
