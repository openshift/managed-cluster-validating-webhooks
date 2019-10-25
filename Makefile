SHELL := /bin/bash

IMG ?= quay.io/lseelye/python3-webhookbase

.PHONY: build-base
build-base: build/Dockerfile
	docker build -t $(IMG):latest -f build/Dockerfile .
