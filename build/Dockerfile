# https://github.com/openshift/ocp-build-data/blob/1a16e3dc96b8e4845d4b960628ccbe5edafe0510/streams.yml#L40
FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.17-openshift-4.10 AS builder

RUN mkdir -p /workdir
WORKDIR /workdir
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

####
FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

ENV USER_UID=1001 \
    USER_NAME=webhooks

COPY --from=builder /workdir/build/_output/webhooks /usr/local/bin/

COPY build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}

LABEL io.openshift.managed.name="managed-cluster-validating-webhooks" \
      io.openshift.managed.description="Validating Webhooks for Openshift Dedicated"
