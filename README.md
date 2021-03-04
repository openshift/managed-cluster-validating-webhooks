# Managed Cluster Validating Webhooks

A framework supporting validating webhooks for OpenShift.

- [Managed Cluster Validating Webhooks](#managed-cluster-validating-webhooks)
  - [Updating SelectorSyncSet Template](#updating-selectorsyncset-template)
  - [Development](#development)
    - [Adding New Webhooks](#adding-new-webhooks)
    - [Helper Utils](#helper-utils)
  - [Is The Request Valid and Authorized](#is-the-request-valid-and-authorized)
    - [Building a Response](#building-a-response)
    - [Sending Responses](#sending-responses)
    - [Writing Unit Tests](#writing-unit-tests)
    - [Local Live Testing](#local-live-testing)
      - [Create a Repository](#create-a-repository)
      - [Build and Push the Image](#build-and-push-the-image)
      - [Pare Down Your Daemonset (Optional)](#pare-down-your-daemonset-optional)
      - [Deploy the Image](#deploy-the-image)
      - [Test Your Changes](#test-your-changes)
    - [End to End Testing](#end-to-end-testing)
  - [Disabling Webhooks](#disabling-webhooks)
    - [Removing a Webhook](#removing-a-webhook)

## Updating SelectorSyncSet Template

Ensure the git branch is current and run `make syncset`. The updated Template will be  [build/selectorsyncset.yaml](build/selectorsyncset.yaml) by default.

## Development

Each Webhook must register with, and therefor satisfy the interface specified in [pkg/webhooks/register.go](pkg/webhooks/register.go):

```go
// imports shown here for clarity
import (
  admissionregv1 "k8s.io/api/admissionregistration/v1"
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
  MatchPolicy() *admissionregv1.MatchPolicyType
  // Rules is a slice of rules on which this hook should trigger
  Rules() []admissionregv1.RuleWithOperations
  // SideEffects are what side effects, if any, this hook has. Refer to
  // https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects
  SideEffects() *admissionregv1.SideEffectClass
  //TimeoutSeconds returns an int32 representing how long to wait for this hook to complete
  TimeoutSeconds() int32
	// Doc returns a string for end-customer documentation purposes.
	Doc() string
	// SyncSetLabelSelector returns the label selector to use in the SyncSet.
	// Return utils.DefaultLabelSelector() to stick with the default
	SyncSetLabelSelector() metav1.LabelSelector
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

## Is The Request Valid and Authorized

The key difference between "valid" and "authorized" is that the former is asking if the incoming request is well-formed whereas the latter is asking if the user making the request is allowed to do so. Each webhook may have a different idea of what a "valid" request looks like, but some common feature may be if the request has a username set.

`Validate` and `Authorized` serve as two entry points for the webserver: First it will ask if the request is valid and then it will ask if it is authorized. Thus, we can speak more about fulfulling the interface requirements for these two methods.

### Building a Response

To create a `Response` object (to reply to the incoming `AdmissionRequest`), one should use `sigs.k8s.io/controller-runtime/pkg/webhook/admission` (often imported as `admissionctl`), which provides several helper functions:

* `Allowed(message string)`
* `Denied(message string) Response`
* `Errored(error int32, message string) Response`

Use these functions once access has been determined, or in the event of some fundamental problem. A common use for `Errored` is when `Validate` fails. Refer to [Sending Responses](#sending-responses) for methods related to sending these `Response` objects back over the HTTP connection.

It is important to retain the UID from the incoming request with the outgoing response. A common pattern for this is:

```go
  var ret admissionctl.Response
  ret = admissionctl.Allowed("Request is allowed")
  ret.UID = request.AdmissionRequest.UID
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
        image: quay.io/app-sre/managed-cluster-validating-webhooks:a324838
```
with
```
        image: quay.io/my-user/managed-cluster-validating-webhooks:latest
```

Once these changes are saved, you should see `validation-webhook-*` pods cycle.
When they have settled, you can confirm that the pod(s) are running with your image.
For example:
```
$ oc describe pod -n openshift-validation-webhook | grep '^ *Image:'
    Image:         quay.io/my-user/managed-cluster-validating-webhooks:latest
```

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
# go run build/syncset.go -showhooks
group-validation
identity-validation
namespace-validation
regular-user-validation
user-validation
```

At this point, we have:

* group-validation
* identity-validation
* namespace-validation
* regular-user-validation
* user-validation

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
        build/syncset.go \
        -exclude identity-validation,namespace-validation \
        -outfile build/selectorsyncset.yaml \
        -image "quay.io/app-sre/managed-cluster-validating-webhooks:\${IMAGE_TAG}"
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

