SHELL := /usr/bin/env bash

TEMPLATEFILES := $(shell find ./templates -type f -name "*.yaml.tmpl")

BASE_IMG=managed-cluster-validating-webhooks
NAMESPACE ?= openshift-validation-webhook
SVCNAME ?= validation-webhook
SANAME ?= validation-webhook
GIT_HASH=$(shell git rev-parse --short=7 HEAD)
IMAGETAG=${GIT_HASH}
CABUNDLECONFIGMAP ?= webhook-cert
VWC_ANNOTATION ?= managed.openshift.io/inject-cabundle-from

IMG ?= quay.io/app-sre/${BASE_IMG}

SELECTOR_SYNC_SET_TEMPLATE_DIR=deploy
BUILD_DIRECTORY=build
SELECTOR_SYNC_SET_DESTINATION=build/selectorsyncset.yaml
REPO_NAME ?= managed-cluster-validating-webhooks

CONTAINER_ENGINE?=docker

default: all
all: build-base build-sss

.PHONY: clean
clean:
	$(CONTAINER_ENGINE) rmi $(REPO_NAME):test $(IMG):$(IMAGETAG) 2>/dev/null || true
	rm -f coverage.log

.PHONY: test-container
test-container:
	$(CONTAINER_ENGINE) build -t $(REPO_NAME):test -f build/Dockerfile.test .

.PHONY: lint
lint: test-container
	# E111 indentation is not a multiple of four
	# E121 continuation line under-indented for hanging indent
	# E127 continuation line over-indented for visual indent
	# E129 visually indented line with same indent as next logical line
	# E401 multiple imports on one line
	# E402 module level import not at top of file
	# E501 line too long (N > 79 characters)
	# E722 do not use bare 'except'
	# W293 blank line contains whitespace
	# W503 line break before binary operator
	# W504 line break after binary operator
	$(CONTAINER_ENGINE) run --rm -v `pwd -P`:`pwd -P` $(REPO_NAME):test /bin/sh -c "cd `pwd`; flake8 --ignore E111,E114,E127,E129,E401,E402,E501,E722,W293,W503,W504 src/"

.PHONY: test
test: test-container
	$(CONTAINER_ENGINE) run --rm -v `pwd -P`:`pwd -P` $(REPO_NAME):test /bin/sh -c "cd `pwd -P`; ./hack/test.sh"

.PHONY: build-sss
build-sss: render test-container
	${CONTAINER_ENGINE} run --rm -v `pwd -P`:`pwd -P` $(REPO_NAME):test /bin/sh -c "cd `pwd -P`; python build/generate_syncset.py -t ${SELECTOR_SYNC_SET_TEMPLATE_DIR} -b ${BUILD_DIRECTORY} -d ${SELECTOR_SYNC_SET_DESTINATION} -r ${REPO_NAME}"

.PHONY: build-base
build-base: lint test build/Dockerfile
	$(CONTAINER_ENGINE) build -t $(IMG):$(IMAGETAG) -f build/Dockerfile . 

.PHONY: push-base
push-base: build/Dockerfile
	$(CONTAINER_ENGINE) push $(IMG):$(IMAGETAG)

.PHONY: skopeo-push
skopeo-push:
	# QUAY_USER and QUAY_TOKEN are supplied as env vars
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

.PHONY: requirements
requirements:
	if [ "$(pip list | grep pipreqs | wc -l)" != "0" ]; then \
		rm -f src/requirements.txt; \
		pipreqs ./; \
		mv requirements.txt src/; \
	else \
		echo "FAILURE please install pipreqs: pip install pipreqs"; \
	fi
