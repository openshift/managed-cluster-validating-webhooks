SHELL := /usr/bin/env bash

# Verbosity
AT_ = @
AT = $(AT_$(V))
# /Verbosity

GIT_HASH := $(shell git rev-parse --short=7 HEAD)
IMAGETAG ?= ${GIT_HASH}

BASE_IMG ?= managed-cluster-validating-webhooks
BASE_PKG_IMG ?= managed-cluster-validating-webhooks-hs-package
IMG_REGISTRY ?= quay.io
IMG_ORG ?= app-sre
IMG ?= $(IMG_REGISTRY)/$(IMG_ORG)/${BASE_IMG}
PKG_IMG ?= $(IMG_REGISTRY)/$(IMG_ORG)/${BASE_PKG_IMG}

SYNCSET_GENERATOR_IMAGE := registry.ci.openshift.org/openshift/release:golang-1.17

BINARY_FILE ?= build/_output/webhooks

GO_SOURCES := $(find $(CURDIR) -type f -name "*.go" -print)
EXTRA_DEPS := $(find $(CURDIR)/build -type f -print) Makefile

# Containers may default GOFLAGS=-mod=vendor which would break us since
# we're using modules.
unexport GOFLAGS
GOOS?=linux
GOARCH?=amd64
GOFLAGS_MOD?=
GOENV=GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 GOFLAGS=${GOFLAGS_MOD}

GOBUILDFLAGS=-gcflags="all=-trimpath=${GOPATH}" -asmflags="all=-trimpath=${GOPATH}"

# do not include this comma-separated list of hooks into the syncset
SELECTOR_SYNC_SET_HOOK_EXCLUDES ?= debug-hook
SELECTOR_SYNC_SET_DESTINATION = build/selectorsyncset.yaml

PACKAGE_RESOURCE_DESTINATION = config/package/resources.yaml.gotmpl
PACKAGE_RESOURCE_MANIFEST = config/package/manifest.yaml

CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
#eg, -v
TESTOPTS ?=

DOC_BINARY := hack/documentation/document.go
# ex -hideRules
DOCFLAGS ?=

default: all

all: test build-image build-package build-sss

.PHONY: test
test: vet $(GO_SOURCES)
	$(AT)go test $(TESTOPTS) $(shell go list -mod=readonly -e ./...)
	$(AT)go run cmd/main.go -testhooks

.PHONY: clean
clean:
	$(AT)rm -f $(BINARY_FILE) coverage.txt

.PHONY: serve
serve:
	$(AT)go run ./cmd/main.go -port 8888

.PHONY: vet
vet:
	$(AT)gofmt -s -l $(shell go list -f '{{ .Dir }}' ./... ) | grep ".*\.go"; if [ "$$?" = "0" ]; then gofmt -s -d $(shell go list -f '{{ .Dir }}' ./... ); exit 1; fi
	$(AT)go vet ./cmd/... ./pkg/...

.PHONY: generate
generate:
	$(AT)go generate ./pkg/config

.PHONY: build
build: $(BINARY_FILE)

$(BINARY_FILE): test $(GO_SOURCES)
	mkdir -p $(shell dirname $(BINARY_FILE))
	$(GOENV) go build $(GOBUILDFLAGS) -o $(BINARY_FILE) ./cmd

.PHONY: build-base
build-base: build-image build-package-image
.PHONY: build-image
build-image: clean $(GO_SOURCES) $(EXTRA_DEPS)
	$(CONTAINER_ENGINE) build -t $(IMG):$(IMAGETAG) -f $(join $(CURDIR),/build/Dockerfile) . && \
	$(CONTAINER_ENGINE) tag $(IMG):$(IMAGETAG) $(IMG):latest

.PHONY: build-package-image
build-package-image: clean $(GO_SOURCES) $(EXTRA_DEPS)
	$(shell sed -i -e "s#REPLACED_BY_PIPELINE#$(IMG):$(IMAGETAG)#g" $(PACKAGE_RESOURCE_DESTINATION))
	$(CONTAINER_ENGINE) build -t $(PKG_IMG):$(IMAGETAG) -f $(join $(CURDIR),/config/package/managed-cluster-validating-webhooks-package.Containerfile) . && \
	$(CONTAINER_ENGINE) tag $(PKG_IMG):$(IMAGETAG) $(PKG_IMG):latest

.PHONY: build-push
build-push:
	build/build_push.sh $(IMG):$(IMAGETAG)

.PHONY: build-push-package
build-push-package:
	build/build_push_package.sh $(PKG_IMG):$(IMAGETAG)

build-sss: syncset
render: syncset
.PHONY: syncset $(SELECTOR_SYNC_SET_DESTINATION)
syncset: $(SELECTOR_SYNC_SET_DESTINATION)
$(SELECTOR_SYNC_SET_DESTINATION):
	$(CONTAINER_ENGINE) run \
		-v $(CURDIR):$(CURDIR):z \
		-w $(CURDIR) \
		-e GOFLAGS=$(GOFLAGS) \
		--rm \
		$(SYNCSET_GENERATOR_IMAGE) \
			go run \
				build/resources.go \
				-exclude $(SELECTOR_SYNC_SET_HOOK_EXCLUDES) \
				-syncsetfile $(@)

render: package
.PHONY: package $(PACKAGE_RESOURCE_DESTINATION)
package: $(PACKAGE_RESOURCE_DESTINATION) $(PACKAGE_RESOURCE_MANIFEST)
$(PACKAGE_RESOURCE_DESTINATION):
	mkdir -p $(shell dirname $(PACKAGE_RESOURCE_DESTINATION))
	$(CONTAINER_ENGINE) run \
		-v $(CURDIR):$(CURDIR):z \
		-w $(CURDIR) \
		-e GOFLAGS=$(GOFLAGS) \
		--rm \
		$(SYNCSET_GENERATOR_IMAGE) \
			go run \
				build/resources.go \
				-packagedir $(shell dirname $(@))

.PHONY: container-test
container-test:
	$(CONTAINER_ENGINE) run \
		-v $(CURDIR):$(CURDIR):z \
		-w $(CURDIR) \
		-e GOFLAGS=$(GOFLAGS) \
		--rm \
		$(SYNCSET_GENERATOR_IMAGE) \
			make test

### Imported
.PHONY: skopeo-push
skopeo-push:
	@if [[ -z $$QUAY_USER || -z $$QUAY_TOKEN ]]; then \
		echo "You must set QUAY_USER and QUAY_TOKEN environment variables" ;\
		echo "ex: make QUAY_USER=value QUAY_TOKEN=value $@" ;\
		exit 1 ;\
	fi
	# QUAY_USER and QUAY_TOKEN are supplied as env vars
	skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
		"docker-daemon:${IMG}:${IMAGETAG}" \
		"docker://${IMG}:latest"
	skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
		"docker-daemon:${IMG}:${IMAGETAG}" \
		"docker://${IMG}:${IMAGETAG}"

.PHONY: skopeo-push-package
skopeo-push-package:
	@if [[ -z $$QUAY_USER || -z $$QUAY_TOKEN ]]; then \
		echo "You must set QUAY_USER and QUAY_TOKEN environment variables" ;\
		echo "ex: make QUAY_USER=value QUAY_TOKEN=value $@" ;\
		exit 1 ;\
	fi
	# QUAY_USER and QUAY_TOKEN are supplied as env vars
	skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
		"docker-daemon:${PKG_IMG}:${IMAGETAG}" \
		"docker://${PKG_IMG}:latest"
	skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
		"docker-daemon:${PKG_IMG}:${IMAGETAG}" \
		"docker://${PKG_IMG}:${IMAGETAG}"


.PHONY: push-base
push-base: build/Dockerfile
	$(CONTAINER_ENGINE) push $(IMG):$(IMAGETAG)
	$(CONTAINER_ENGINE) push $(IMG):latest
	$(CONTAINER_ENGINE) push $(PKG_IMG):$(IMAGETAG)
	$(CONTAINER_ENGINE) push $(PKG_IMG):latest

coverage: coverage.txt
coverage.txt: vet $(GO_SOURCES)
	@./hack/test.sh

.PHONY: docs
docs:
	@# Ensure that the output from the test is hidden so this can be
	@# make docs > docs.json
	@# To hide the rules: make DOCFLAGS=-hideRules docs
	@$(MAKE test)
	@go run $(DOC_BINARY) $(DOCFLAGS)
