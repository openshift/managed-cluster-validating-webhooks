SHELL := /usr/bin/env bash


GIT_HASH := $(shell git rev-parse --short=7 HEAD)
IMAGETAG ?= ${GIT_HASH}

BASE_IMG ?= managed-cluster-validating-webhooks
IMG ?= quay.io/app-sre/${BASE_IMG}

# nb: registry.svc.ci.openshift.org/openshift/release:golang-1.14 doesn't work for this
SYNCSET_GENERATOR_IMAGE := quay.io/app-sre/golang:1.14

BINARY_FILE ?= build/_output/webhooks

GO_SOURCES := $(find $(CURDIR) -type f -name "*.go" -print)
EXTRA_DEPS := $(find $(CURDIR)/build -type f -print) Makefile
GOOS ?= linux
GOARCH ?= amd64
GOENV = GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0
GOBUILDFLAGS = -gcflags="all=-trimpath=$(GOPATH)" -asmflags="all=-trimpath=$(GOPATH)"

# do not include this comma-separated list of hooks into the syncset
SELECTOR_SYNC_SET_HOOK_EXCLUDES ?= debug-hook
SELECTOR_SYNC_SET_DESTINATION = build/selectorsyncset.yaml

CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
#eg, -v
TESTOPTS ?=

DOC_BINARY := hack/documentation/document.go
# ex -hideRules
DOCFLAGS ?= 

default: all

all: test build-image build-sss

.PHONY: test
test: vet $(GO_SOURCES)
	@go test $(TESTOPTS) $(shell go list -mod=readonly -e ./...)
	@go run cmd/main.go -testhooks

.PHONY: clean
clean:
	@rm -f $(BINARY_FILE) coverage.txt

.PHONY: serve
serve:
	@go run ./cmd/main.go -port 8888

.PHONY: vet
vet:
	@gofmt -s -l $(shell go list -f '{{ .Dir }}' ./... ) | grep ".*\.go"; if [ "$$?" = "0" ]; then gofmt -s -d $(shell go list -f '{{ .Dir }}' ./... ); exit 1; fi
	@go vet ./cmd/... ./pkg/...

.PHONY: build
build: $(BINARY_FILE)

$(BINARY_FILE): test $(GO_SOURCES)
	mkdir -p $(shell dirname $(BINARY_FILE))
	$(GOENV) go build $(GOBUILDFLAGS) -o $(BINARY_FILE) ./cmd

.PHONY: build-base
build-base: build-image
.PHONY: build-image
build-image: clean $(GO_SOURCES) $(EXTRA_DEPS)
	$(CONTAINER_ENGINE) build -t $(IMG):$(IMAGETAG) -f $(join $(CURDIR),/build/Dockerfile) . && \
	$(CONTAINER_ENGINE) tag $(IMG):$(IMAGETAG) $(IMG):latest

build-sss: syncset
render: syncset
.PHONY: syncset $(SELECTOR_SYNC_SET_DESTINATION)
syncset: $(SELECTOR_SYNC_SET_DESTINATION)
# \$${IMAGE_TAG} will put a literal ${IMAGE_TAG} in the output, which is
# required for the Template parsing
$(SELECTOR_SYNC_SET_DESTINATION):
	$(CONTAINER_ENGINE) run \
		-v $(CURDIR):$(CURDIR) \
		-w $(CURDIR) \
		--rm \
		$(SYNCSET_GENERATOR_IMAGE) \
			go run \
				build/syncset.go \
				-exclude $(SELECTOR_SYNC_SET_HOOK_EXCLUDES) \
				-outfile $(@) \
				-image "$(IMG):\$${IMAGE_TAG}"

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


.PHONY: push-base
push-base: build/Dockerfile
	$(CONTAINER_ENGINE) push $(IMG):$(IMAGETAG)

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
