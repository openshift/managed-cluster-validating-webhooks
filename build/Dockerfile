FROM registry.svc.ci.openshift.org/openshift/release:golang-1.14 AS builder

RUN mkdir -p /workdir
WORKDIR /workdir
COPY . .
RUN go mod vendor && make build

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

LABEL io.openshift.managed.name="managed-cluster-validating-webhooks" \
  io.openshift.managed.description="Validating Webhooks for Openshift Dedicated"

COPY --from=builder /workdir/build/_output/webhooks /usr/local/bin/
COPY --from=builder /workdir/build/_output/injector /usr/local/bin/

ADD build/bin/* /usr/local/bin/

ENV USER_UID=1000 \
  USER_NAME=webhooks
RUN /usr/local/bin/user_setup

USER ${USER_UID}

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]