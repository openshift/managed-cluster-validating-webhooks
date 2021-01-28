# Managed Cluster Validating Webhooks

A framework supporting validating webhooks for OpenShift.

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

### Writing Tests

Unit tests are important to ensure that webhooks behave as expected, and to help with that process, there is a [testutils](pkg/testutils/testutils.go) helper package designed to unify several processes. The package exports:

* `CanCanNot`
* `CreateFakeRequestJSON`
* `CreateHTTPRequest`
* `SendHTTPRequest`

The first function, `CanCanNot`, is very simple and designed to make test failure messages gramatically correct for. The three other functions are much more important to the testing process.

The three helper functions are intended to provide for more integration style tests than true unit tests, as they assist in turning a specific set of test criteria a JSON representation and sending via `net/http/httptest` to the webhook's `Authorized`. When using `testutils.SendHTTPRequest`, the response is a `Response` object that can be used in the test suite to access the result of the webhook.

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

