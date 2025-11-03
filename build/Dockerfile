ARG BASE_IMAGE=registry.access.redhat.com/ubi9/go-toolset:1.24
FROM ${BASE_IMAGE} AS builder

WORKDIR /opt/app-root/src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=1 GOEXPERIMENT=boringcrypto GOFLAGS=-mod=mod \
    go build -buildvcs=false -gcflags="all=-trimpath=/opt/app-root/src" -asmflags="all=-trimpath=/opt/app-root/src" -tags="fips_enabled" \
    -o webhooks ./cmd

####
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

ENV USER_UID=1001 \
    USER_NAME=webhooks

COPY --from=builder /opt/app-root/src/webhooks /usr/local/bin/

COPY build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}

LABEL io.openshift.managed.name="managed-cluster-validating-webhooks" \
      io.openshift.managed.description="Validating Webhooks for Openshift Dedicated"
