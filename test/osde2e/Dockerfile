FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_9_1.22  AS builder

ENV PKG=/go/src/github.com/openshift/managed-cluster-validating-webhooks/test/osde2e/
WORKDIR ${PKG}

# Copy go.mod and go.sum to the working directory
COPY ../../go.mod ../../go.sum ./
COPY ../../LICENSE .

COPY ./test/osde2e/ .
RUN go mod vendor
RUN make build

FROM registry.redhat.io/rhel9-2-els/rhel:9.2
WORKDIR /
RUN mkdir /licenses
COPY --from=builder /go/src/github.com/openshift/managed-cluster-validating-webhooks/test/osde2e/out/validation-webhook .
COPY --from=builder /go/src/github.com/openshift/managed-cluster-validating-webhooks/test/osde2e/LICENSE /licenses/.

ENTRYPOINT [ "/validation-webhook" ]
USER 65532:65532

LABEL name="validation-webhook"
LABEL description="A comprehensive test framework used for Service Delivery to validate webhook"
LABEL summary="CLI tool for validating the network migration of ROSA clusters"
LABEL com.redhat.component="validation-webhook"
LABEL io.k8s.description="validation-webhook"
LABEL io.k8s.display-name="validation-webhook"
LABEL io.openshift.tags="data,images"