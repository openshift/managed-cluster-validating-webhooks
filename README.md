# Managed Cluster Validating Webhooks

# This is a testing PR

Overview & Purpose

The project offers a framework for admission webhooks tailored for OpenShift-managed clusters. Its modularity supports adding new policy-specific webhooks easily.

Though named for validating webhooks, it supports mutating webhooks too, the core difference being their response options (mutate vs reject)


Repository Structure
Key directories and files include:
cmd/ – main entrypoint(s) for the webhook server.
pkg/webhooks/ – contains implementations for each webhook.
build/ – scripts and templates (e.g., selectorsyncset.yaml) needed for deployment.
config/, designs/, docs/, hack/, test/e2e/ – auxiliary configs, design specs, documentation, tooling, and end-to-end tests.
Makefile, go.mod, go.sum, LICENSE, OWNERS – build and governance infrastructure.
pkg/testutils – utility helpers for testing.

Core Components

Webhook Framework (pkg/webhooks/)

Defines a common Webhook interface: methods to identify request types, authenticate users, validate or mutate, and return structured admission responses appropriately.


Implements various webhook handlers, for example:


namespace.go for namespace-level constraints.
(Likely others like pod, SCC, network policy, etc.)


Each handler encapsulates request examination logic and policy rules.

Server (cmd/webhooks/)
Initializes the webhook HTTP server, reads TLS certificates, sets up routing for different webhook endpoints (/namespace-validation, /pod-validation, etc.).
Entrypoint compiles all registered webhooks and configures them in an HTTPS server listening per OpenShift requirements.

Deployment Resources
Selectorsyncset.yaml 
A central manifest that defines how resources are deployed on a managed cluster via Hive’s SelectorSyncSet:
Declares a namespace openshift-validation-webhook, service account, roles, and role bindings.
Deploys:


A Service for webhook traffic over HTTPS.
A DaemonSet ensuring the webhook server runs on all master/control-plane nodes.
Multiple ValidatingWebhookConfiguration resources, each targeting a specific API group/resource/operation.


Webhook configs define:


Client config: service name, namespace, path (e.g., /namespace-validation)
Rules: targeting specific resources (namespaces, pods, image policies, etc.)
Failure policies (Ignore or Fail), side effects, request timeouts github.com.


A framework supporting [validating admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) for OpenShift.

- [Managed Cluster Validating Webhooks](#managed-cluster-validating-webhooks)
- [This is a testing PR](#this-is-a-testing-pr)
  - [Updating SelectorSyncSet Template](#updating-selectorsyncset-template)
  - [Updating namespace and service account list](#updating-namespace-and-service-account-list)
  - [Updating documentation files](#updating-documentation-files)
  - [Development](#development)
    - [Adding New Webhooks](#adding-new-webhooks)
    - [Helper Utils](#helper-utils)
    - [Mutating Webhooks](#mutating-webhooks)
  - [Is The Request Valid and Authorized](#is-the-request-valid-and-authorized)
    - [Building a Response](#building-a-response)
    - [Sending Responses](#sending-responses)
    - [Writing Unit Tests](#writing-unit-tests)
    - [Local Live Testing](#local-live-testing)
      - [Create a Repository](#create-a-repository)
      - [Build and Push the Image](#build-and-push-the-image)
      - [Prevent Overwriting (Hive-Managed Clusters)](#prevent-overwriting-hive-managed-clusters)
      - [Pare Down Your Daemonset (Optional)](#pare-down-your-daemonset-optional)
      - [Deploy the Image](#deploy-the-image)
    - [Create the ValidatingWebhookConfiguration](#create-the-validatingwebhookconfiguration)
      - [Update Other Resources](#update-other-resources)
      - [Test Your Changes](#test-your-changes)
    - [End to End Testing](#end-to-end-testing)
  - [Disabling Webhooks](#disabling-webhooks)
    - [Removing a Webhook](#removing-a-webhook)

## Updating SelectorSyncSet Template

Ensure the git branch is current and run `make syncset`. The updated Template will be  [build/selectorsyncset.yaml](build/selectorsyncset.yaml) by default.

## Updating namespace and service account list

Ensure the git branch is current and run `make generate`. The updated lists will be written to [pkg/config/namespaces.go](pkg/config/namespaces.go). [Documentation should also be regenerated](#updating-documentation-files) to ensure the ConfigMaps specified are up-to-date.

## Updating documentation files

Ensure the git branch is current and run `make docs > docs/webhooks.json && make DOCFLAGS=-hideRules docs > docs/webhooks-short.json`.

## Development

Each Webhook must register with, and therefore satisfy the interface specified in [pkg/webhooks/register.go](pkg/webhooks/register.go):

```go
// imports shown here for clarity
import (
  admissionregv1 "k8s.io/api/admissionregistration/v1"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Webhook interface
type Webhook interface {
	// Authorized will determine if the request is allowed
	Authorized(request admissionctl.Request) admissionctl.Response
	// GetURI returns the URI for the webhook
	GetURI() string
	// Validate will validate the incoming request
	Validate(admissionctl.Request) bool
	// Name is the name of the webhook
	Name() string
	// FailurePolicy is how the hook config should react if k8s can't access it
	FailurePolicy() admissionregv1.FailurePolicyType
	// MatchPolicy mirrors validatingwebhookconfiguration.webhooks[].matchPolicy.
	// If it is important to the webhook, be sure to check subResource vs
	// requestSubResource.
	MatchPolicy() admissionregv1.MatchPolicyType
	// Rules is a slice of rules on which this hook should trigger
	Rules() []admissionregv1.RuleWithOperations
	// ObjectSelector uses a *metav1.LabelSelector to augment the webhook's
	// Rules() to match only on incoming requests which match the specific
	// LabelSelector.
	ObjectSelector() *metav1.LabelSelector
	// SideEffects are what side effects, if any, this hook has. Refer to
	// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects
	SideEffects() admissionregv1.SideEffectClass
	// TimeoutSeconds returns an int32 representing how long to wait for this hook to complete
	TimeoutSeconds() int32
	// Doc returns a string for end-customer documentation purposes.
	Doc() string
	// SyncSetLabelSelector returns the label selector to use in the SyncSet.
	// Return utils.DefaultLabelSelector() to stick with the default
	SyncSetLabelSelector() metav1.LabelSelector
	// ClassicEnabled will return true if the webhook should be deployed to OSD/ROSA Classic clusters
	ClassicEnabled() bool
	// HypershiftEnabled will return true if the webhook should be deployed to ROSA HCP clusters
	HypershiftEnabled() bool
}
```

The first four methods (`Authorized`, `GetURI`, `Validate` and `Name`) are involved with the process of handling the incoming JSON payload from the API server. `GetURI` and `Name` prepare the webserver to send to determine if the request is `Authorized` and to `Validate` ensures that the structure of the `AdmissionRequest` is appropriate, _not_ if the request should be permitted (this functionality is up to the webhook author to implement, and is not part of the interface).

The remaining methods (and also including `GetURI` and `Name`) are involved with [rendering YAML](#updating-selectorsyncset-template).

### Adding New Webhooks

Registering involves creating a file in [pkg/webhooks](pkg/webhooks) (eg [add_namespace_hook.go](pkg/webhooks/add_namespace_hook.go)) which calls the `Register` function exported from [register.go](pkg/webhooks/register.go):

```go
// pkg/webhooks/add_namespace_hook.go

package webhooks

import (
  "github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/namespace"
)

func init() {
  Register(namespace.WebhookName, func() Webhook { return namespace.NewWebhook() })
}
```

The signature is `Register(string, WebhookFactory)`, where a `WebhookFactory` is `type WebhookFactory func() Webhook`.

### Helper Utils

The [utils package](pkg/webhooks/utils/utils.go) provides a string slice content checker (`SliceContains(string, []string) bool`) since it's a common task to see if a group or username is a member of some safelisted list.

### Mutating Webhooks

Despite its name, this repository has basic support for deploying mutating webhooks alongside validating ones due to their similarity. The differences between the two webhook types boil down to the types of decisions (`Response`s) they're allowed to return to the API server. Just like validating webhooks, mutating webhooks can decide that a request is `Allowed`, `Denied`, or `Errored` (see *[Building a Response](#building-a-response)* below). Unlike validating webhooks, however, mutating webhooks may instead decide that a request can be allowed only if some changes are made (i.e., `Patched`). `Patched` decisions contain a RFC 6902 ([JSONPatch](https://jsonpatch.com/)) string that describes the necessary mutations.

For example, the [service-mutation webhook](pkg/webhooks/service/service.go) enforces an AWS managed policy requirement that ELBs are tagged with `red-hat-managed=true` by mutating all CREATE and UPDATE operations on LoadBalancer-type `Services` such that they contain the annotation `service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags: red-hat-managed=true`. For a CREATE operation on a `Service` that's missing the necessary annotation, the JSONPatch embedded within the `Patched` Response might look like:

```json
{
    "op": "add",
    "path": "/metadata/annotations/service.beta.kubernetes.io~1aws-load-balancer-additional-resource-tags",
    "value": "red-hat-managed=true"
}
```

MutatingWebhooks are indicated by their name: if your Webhook's `Name()` function returns a string ending in `-mutation`, then [resources.go](build/resources.go) will generate a MutatingWebhookConfiguration (instead of a ValidatingWebhookConfiguration) when building the [SelectorSyncSet](build/selectorsyncset.yaml) and [PKO package](docs/hypershift.md). Beyond that, this repo does not descriminate between MutatingWebhooks and ValidatingWebhooks, and you may assume any documentation in this repo applies to both Webhook types unless otherwise noted.

## Is The Request Valid and Authorized

The key difference between "valid" and "authorized" is that the former is asking if the incoming request is well-formed whereas the latter is asking if the user making the request is allowed to do so. Each webhook may have a different idea of what a "valid" request looks like, but some common feature may be if the request has a username set.

`Validate` and `Authorized` serve as two entry points for the webserver: First it will ask if the request is valid and then it will ask if it is authorized. Thus, we can speak more about fulfulling the interface requirements for these two methods.

### Building a Response

To create a `Response` object (to reply to the incoming `AdmissionRequest`), one should use `sigs.k8s.io/controller-runtime/pkg/webhook/admission` (often imported as `admissionctl`), which provides several helper functions:

* `Allowed(message string)`
* `Denied(message string) Response`
* `Errored(error int32, message string) Response`
* `Patched(message string, patches ...jsonpatch.JsonPatchOperation) Response` ([mutating webhooks](#mutating-webhooks) only)

Use these functions once access has been determined, or in the event of some fundamental problem. A common use for `Errored` is when `Validate` fails. Refer to [Sending Responses](#sending-responses) for methods related to sending these `Response` objects back over the HTTP connection.

It is important to retain the UID from the incoming request with the outgoing response. A common pattern for this is:

```go
  var ret admissionctl.Response
  ret = admissionctl.Allowed("Request is allowed")
  ret.UID = request.AdmissionRequest.UID
  return ret
```

Mutating webhooks, however, should use `admissionctl.Complete()` instead of manually setting the UID when issuing `Patched` decisions. For example:

```go
  var ret admissionctl.Response
  ret = admissionctl.Patched("Request is only allowed if mutated", jsonPatchOp)
  ret.Complete(request)
  return ret
```

### Sending Responses

Once a [response is built](#building-a-response), it must be sent back to the HTTP client. This is done by returning the `admissionctl.Response` in the `Authorized` method. This structure can be [built up with the helpers mentioned above](#building-a-response).

### Writing Unit Tests

Unit tests are important to ensure that webhooks behave as expected, and to help with that process, there is a [testutils](pkg/testutils/testutils.go) helper package designed to unify several processes. The package exports:

* `CanCanNot`
* `CreateFakeRequestJSON`
* `CreateHTTPRequest`
* `SendHTTPRequest`

The first function, `CanCanNot`, is very simple and designed to make test failure messages gramatically correct for. The three other functions are much more important to the testing process.

The three helper functions are intended to provide for more integration style tests than true unit tests, as they assist in turning a specific set of test criteria a JSON representation and sending via `net/http/httptest` to the webhook's `Authorized`. When using `testutils.SendHTTPRequest`, the response is a `Response` object that can be used in the test suite to access the result of the webhook.

### Local Live Testing

Build and test your changes against your own cluster.
Here is a [recorded demo](https://drive.google.com/file/d/1UaMz-siFDRaSKPVKxjLOneqGgbBuwpBF/view) of this process.

#### Create a Repository

Make sure you have a repository to host the image you are going to build.
It must be **public** so your cluster is able to download the image.
For subsequent steps, you will need the name of the registry, the organization, and the repository.
For example, in the image URI `quay.io/my-user/managed-cluster-validating-webhooks:latest`:
- `quay.io` is the *registry*
- `my-user` is the *organization*
- `managed-cluster-validating-webhooks` is the *repository*
- `latest` is the *image tag*

#### Build and Push the Image

Use `make build-base` to build and tag the image; and `make push-base` to push it.
In order to use your personal repository, you can override any of the components of this URI by setting the following variables:
- `IMG_REGISTRY` overrides the *registry* (default: `quay.io`)
- `IMG_ORG` overrides the *organization* (default: `app-sre`)
- `BASE_IMG` overrides the *repository name* (default: `managed-cluster-validating-webhooks`)
- `IMAGETAG` overrides the *image tag*. (By default this is the current commit hash of your local clone of the git repository; but `make build-base` will also always tag `latest`)

For example, to build, tag, and push `quay.io/my-user/managed-cluster-validating-webhooks:latest`, you can run:

```
make IMG_ORG=my-user build-base push-base
```

#### Prevent Overwriting (Hive-Managed Clusters)

If you are using an OSD cluster managed by hive, the resources in the `openshift-validation-webhook` project are controlled by SelectorSyncSets.
By default, hive will periodically refresh these resources, reverting any changes you make according to the instructions below.
To avoid this, [pause hive syncing for your cluster](https://github.com/openshift/ops-sop/blob/master/v4/knowledge_base/pause-syncset.md).

#### Pare Down Your Daemonset (Optional)

**Note:** Editing the daemonset requires elevated privileges.

By default, the image will run on all master nodes.
For testing purposes, you may find it easier to run on only one node.
To facilitate this:
1. Pick a master node to use. Any one will do. For example:
   ```
   $ oc get node | grep master | head -1
   ip-10-0-147-186.ec2.internal   Ready    master         3h44m   v1.19.0+f173eb4
   ```
2. Give the node a unique label. For example:
   ```
   $ oc label node ip-10-0-147-186.ec2.internal mcvw-test=true
   node/ip-10-0-147-186.ec2.internal labeled
   ```
3. Edit the `validation-webhook` daemonset's `.spec.template.spec.affinity.nodeAffinity`, replacing the `matchExpressions` entry for `node-role.kubernetes.io/master` to match your label instead.
   For example, to match the label from step 2, run:
   ```
   oc edit -n openshift-validation-webhook daemonset validation-webhook
   ```
   and replace
   ```
           nodeAffinity:
             requiredDuringSchedulingIgnoredDuringExecution:
               nodeSelectorTerms:
               - matchExpressions:
                 - key: node-role.kubernetes.io/master
                   operator: In
                   values:
                   - ""
   ```
   with
   ```
           nodeAffinity:
             requiredDuringSchedulingIgnoredDuringExecution:
               nodeSelectorTerms:
               - matchExpressions:
                 - key: mcvw-test   # <== your label's key
                   operator: In
                   values:
                   - "true"         # <== your label's value
   ```

Once these changes are saved, you should see `validation-webhook-*` pods cycle.
When they have settled, you can confirm that only one pod is running and that it is running on your desired node.
For example:

```
$ oc describe pod -n openshift-validation-webhook | grep ^Node:
Node:         ip-10-0-147-186.ec2.internal/10.0.147.186
```

#### Deploy the Image

**Note:** Editing the daemonset requires elevated privileges.

Edit the `validation-webhook` daemonset's `.spec.template.spec.containers[0].image`, replacing it with the URI of the image you built and pushed [above](#build-and-push-the-image).
For example, if you created `quay.io/my-user/managed-cluster-validating-webhooks:latest`, replace
```
        image: quay.io/app-sre/managed-cluster-validating-webhooks@sha256:f33f879a9e8b0dc5b0481f75ba5eb8422a8a9b06acf70330794eb564ee31e9e5
```
with
```
        image: quay.io/my-user/managed-cluster-validating-webhooks:latest
```
(You can specify your custom image by tag or by digest; the latter is only necessary if quay is down.)

Once these changes are saved, you should see `validation-webhook-*` pods cycle.
When they have settled, you can confirm that the pod(s) are running with your image.
For example:
```
$ oc describe pod -n openshift-validation-webhook | grep '^ *Image:'
    Image:         quay.io/my-user/managed-cluster-validating-webhooks:latest
```

### Create the ValidatingWebhookConfiguration
Once the image is pulled to your cluster, you will need to create the ValidatingWebhookConfiguration.  You should notice that the `build/selectorysyncset.yaml` file will have a new section containing your webhook's ValidatingWebhookConfiguration.  It should look something similar to this.
```
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
  creationTimestamp: null
  name: sre-new-webhook
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    service:
      name: new-webhook
      namespace: openshift-validation-webhook
      path: /networkpolicies-validation
  failurePolicy: Ignore
  matchPolicy: Equivalent
  name: new-webhook-validation.managed.openshift.io
  rules:
  - apiGroups:
    - networking.k8s.io
    apiVersions:
    - '*'
    operations:
    - CREATE
    resources:
    - networkpolicies
    scope: Namespaced
  sideEffects: None
  timeoutSeconds: 2
```

Save this part of the selectorsyncset.yaml as a its own yaml file and apply it to your cluster.

```
oc apply -f my_webhook.yaml
```

Now you can view that your webhook is registered and running with:
```
oc get validatingwebhookconfigurations -A
```

#### Update Other Resources
If your changes resulted in a delta to [selectorsyncset.yaml](build/selectorsyncset.yaml), you must manually edit the corresponding resources to apply those changes.

**TODO:** More details on this.

#### Test Your Changes

Now that your cluster is running your modified code, you can do whatever is necessary to validate your changes.

### End to End Testing

End to End testing is managed by the [osde2e repo](https://github.com/openshift/osde2e/)

* [Validation Webhook](https://github.com/openshift/osde2e/blob/main/pkg/e2e/verify/validation_webhook.go)
* [Namespace Webhook](https://github.com/openshift/osde2e/blob/main/pkg/e2e/verify/namespace_webhook.go)
* [User Webhook](https://github.com/openshift/osde2e/blob/main/pkg/e2e/verify/user_webhook.go)
* [Identity Webhook](https://github.com/openshift/osde2e/blob/main/pkg/e2e/verify/identity_webhook.go)

## Disabling Webhooks

List the webhooks (if you don't know them already):

```shell
# go run build/resources.go -syncsetfile tmp -showhooks
clusterlogging-validation
hiveownership-validation
imagecontentpolicies-validation
namespace-validation
pod-validation
prometheusrule-validation
regular-user-validation
regular-user-validation-osd
scc-validation
techpreviewnoupgrade-validation
```

At this point, we have:

* clusterlogging-validation
* hiveownership-validation
* imagecontentpolicies-validation
* namespace-validation
* pod-validation
* prometheusrule-validation
* regular-user-validation
* regular-user-validation-osd
* scc-validation
* techpreviewnoupgrade-validation
* ingress-config-validation

In the [Makefile](/Makefile), the `SELECTOR_SYNC_SET_HOOK_EXCLUDES` variable is used to control which are excluded. By default, it is set to `debug-hook`, in case one should come to appear at some time in the future.

Temporarily disable the `identity-validation` and `namespace-validation` hooks, set that same variable in the Makefile:

```makefile
SELECTOR_SYNC_SET_HOOK_EXCLUDES ?= debug-hook,identity-validation,namespace-validation
```

Then at the shell run:

```shell
# make syncset
docker run \
    -v /Users/youruser/git/github.com/openshift/managed-cluster-validating-webhooks:/Users/youruser/git/github.com/openshift/managed-cluster-validating-webhooks \
    -w /Users/youruser/git/github.com/openshift/managed-cluster-validating-webhooks \
    --rm \
    golang:1.14 \
      go run \
        build/resources.go \
        -exclude identity-validation,namespace-validation \
        -outfile build/selectorsyncset.yaml
# truncated ...
```

Commit the Makefile and resulting `build/selectorsyncset.yaml` and deploy it with the normal workflows.

### Removing a Webhook

To delete a webhook one must delete the associated files and re-run `make`. Rerunning `make` will rebuild the binary, container image, and `build/selectorsyncset.yaml` file. The files are the `add_` files as well as the entire package. To remove the Namespace webhook:

```shell
# rm -fr pkg/webhooks/add_namespace_hook.go pkg/webhooks/namespace
pkg/webhooks/add_namespace_hook.go
pkg/webhooks/namespace/namespace_test.go
pkg/webhooks/namespace/namespace.go
pkg/webhooks/namespace
# make
```

Commit all changes and deploy as normal.

Once the code changes are complete, remove the undesired `ValidatingWebhookConfiguration` object(s) manually from the cluster.
