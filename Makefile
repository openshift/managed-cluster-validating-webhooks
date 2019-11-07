SHELL := /usr/bin/env bash

TEMPLATEFILES := $(shell find ./templates -type f -name "*.yaml.tmpl")

NAMESPACE ?= openshift-validation-webhook
SVCNAME ?= validation-webhook
SANAME ?= validation-webhook
IMAGETAG ?= latest
CABUNDLECONFIGMAP ?= webhook-cert
VWC_ANNOTATION ?= managed.openshift.io/inject-cabundle-from

IMG ?= quay.io/lseelye/python3-webhookbase

default: all
all: build-base render

.PHONY: build-base
build-base: build/Dockerfile
	docker build -t $(IMG):$(IMAGETAG) -f build/Dockerfile . && docker push $(IMG):$(IMAGETAG)

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
