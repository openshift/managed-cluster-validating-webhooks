FROM registry.ci.openshift.org/openshift/release:rhel-8-release-golang-1.18-openshift-4.12 AS builder

RUN mkdir -p /workdir
WORKDIR /workdir
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

####
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.7-1107

ENV USER_UID=1001 \
    USER_NAME=webhooks

COPY --from=builder /workdir/build/_output/webhooks /usr/local/bin/

COPY build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}

LABEL io.openshift.managed.name="managed-cluster-validating-webhooks" \
      io.openshift.managed.description="Validating Webhooks for Openshift Dedicated"
