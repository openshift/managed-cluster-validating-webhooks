FROM registry.ci.openshift.org/openshift/release:golang-1.16 AS builder

RUN mkdir -p /workdir
WORKDIR /workdir
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

LABEL io.openshift.managed.name="managed-cluster-validating-webhooks" \
  io.openshift.managed.description="Validating Webhooks for Openshift Dedicated"

COPY --from=builder /workdir/build/_output/webhooks /usr/local/bin/

ADD build/bin/* /usr/local/bin/

ENV USER_UID=1000 \
  USER_NAME=webhooks
RUN /usr/local/bin/user_setup

USER ${USER_UID}

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]
