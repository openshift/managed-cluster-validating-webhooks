.DEFAULT_GOAL := build

CONTAINER_ENGINE ?= podman
OUT_DIR := $(DIR)out


build:
	mkdir -p "$(OUT_DIR)"
	go test -v -c -o "$(OUT_DIR)"/validation-webhook

build-image:
	${CONTAINER_ENGINE} build -t validation-webhook:latest  -f ./Dockerfile ../../
