# Managed Cluster Validating Webhooks

A Flask app designed to act as a webhook admission controller for OpenShift.

## Webhooks

### Group Validation

Configuration for this webhook is provided by environment variables:

* `GROUP_VALIDATION_PREFIX` - Group prefix to apply the webhook, such as `osd-` to apply to `CREATE`, `UPDATE`, `DELETE` operations on groups starting with `osd-`. (default: `osd-sre-`)
* `GROUP_VALIDATION_ADMIN_GROUP` - Admin groups, which the requestor must be a member in order to have access granted. This is comma-separated. (default: `osd-sre-admins,osd-sre-cluster-admins`)
* `DEBUG_GROUP_VALIDATION` - Debug the webhook? Set to `True` to enable, all other values (including absent) disable. (default: False)

### Subscription Validation

Restrict dedicated-admins to creating `Subscription` objects with `.spec.sourceNamespace` from a pre-approved list. The list is specified by environment variable:

* `SUBSCRIPTION_VALIDATION_NAMESPACES` - Comma-separated list of namespaces for which dedicated-admins are allowed to use as `.spec.sourceNamespace` in `Subscription` objects. (default "openshift-operators")
* `DEBUG_SUBSCRIPTION_VALIDATION` - Debug the hook (not currently used)

## How it works

In order for a validating webhook to talk to the code which is performing the validation (eg, the code in this repository), which is running in-cluster, Kubernetes needs to talk to it via a `Service` over HTTPS. This forces the Python Flask app to serve itself with a TLS certificate and the corresponding webhook configuration to specify the CA Bundle (`caBundle`) that matches up for those TLS certs.

The TLS cert is provisioned by using the [openshift-ca-operator](https://github.com/openshift/service-ca-operator). Refer to its documentation for how TLS keys are requested and stored. See also: [02-webhook-cacert.configmap.yaml.tmpl](/templates/02-webhook-cacert.configmap.yaml.tmpl) and [05-group-validation-webhook.service.yaml.tmpl](/templates/05-group-validation-webhook.service.yaml.tmpl).

Getting the TLS certificates is only part of the battle, as the operator does not inject them into the `ValidatingWebhookConfiguration`. To accomplish that, a small Python script has been written that is used as an `initContainer` in the Deployment of the webhook framework. The "injector" script, when run, will find all `ValidatingWebhookConfiguration` objects with an `managed.openshift.io/inject-cabundle-from` annotation. The annotation's value is in the format `namespace/configmap` from whence the CA Bundle can be found (as the key `service-ca.crt`). Thus an annotation `managed.openshift.io/inject-cabundle-from: openshift-validation-webhook/webhook-cert` will have the "injector" script look in the `openshift-validation-webhook` `Namespace` for the `webhook-cert` `ConfigMap` to contain a `service-ca.crt` key and therein, a PEM encoded certificate. The certificate is base64-encoded and set as the `caBundle` for each webhook defined in the `ValidatingWebhookConfiguration`.

## Development

### Adding New Webhooks

In order to add new webhooks, create a new Python file in [src/webhook](src/webhook), following the pattern from [src/webhook/group_validation.py](src/webhook/group_validation.py). Add an entry to [src/webhook/__init__.py](src/webhook/__init__.py) in the pattern of the group validation webhook.

#### Register with the Flask application

To register your webhook with the Flask app:

```python
# src/webhook/__init__.py
from flask import Flask
from flask import request

app = Flask(__name__,instance_relative_config=True)

from webhook import group_validation
app.register_blueprint(group_validation.bp)

from webhook import your_hook
app.register_blueprint(your_hook.bp)
```

#### Adding YAML Manifests

To add a new YAML Manifest:

Create a new file in [templates](/templates) directory with a `10-` prefix, ex `10-your-hook.ValidatingWebhookConfiguration.yaml.tmpl` with contents:

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata: 
  name: your-webhook-name-here
  annotations:
    # Typically  managed.openshift.io/inject-cabundle-from: namespace/configmap
    # The configmap must have the cert in PEM format in a key named service-ca.crt.
    # Each webhook in this object with a service clientConfig will have the bundle injected.
    #VWC_ANNOTATION#: #NAMESPACE#/#CABUNDLECONFIGMAP#
webhooks:
  - clientConfig:
      service:
        namespace: #NAMESPACE#
        name: #SVCNAME#
        path: /your-webhook
    failurePolicy:
      # What to do if the hook itself fails (Ignore/Fail)
    name: your-webhook.managed.openshift.io
    rules:
      - operations:
          # operations list
        apiGroups:
          # apiGroups list
        apiVersions:
          # apiVersions list
        resources:
          # resources List
```

From here, `make render` will populate [deploy](/deploy) with YAML manifests that can be `oc apply` to the cluster in question. Note that new hooks require a restart of the Flask application.

### Request Helpers

There are helper methods within the [src/webhook/request_helper](src/webhook/request_helper) to aid with:

* [Incoming request validation](src/webhook/request_helper/validate.py)
* [Formulating the response JSON body](src/webhook/request_helper/responses.py)

To use the request validation:

```python
# src/webhook/your_hook.py
from flask import request, Blueprint
import json

from webhook.request_helper import validate, responses
@bp.route('/your-webhook', methods=('GET','POST'))
def handle_request():
  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except:
    # if anything goes wrong, it's not valid.
    valid = False
  if not valid:
    return responses.response_invalid()
  # ... normal hook flow
```

To use the response helpers:

```python
# src/webhook/your_hook.py
from flask import request, Blueprint
import json

from webhook.request_helper import responses
@bp.route('/your-webhook', methods=('GET','POST'))
def handle_request():
  # ...

  # request is the object coming from the webhook
  # request.json converts to JSON document, and the request key therein has the interesting data
  request_body = request.json['request']

  # Invalid request came in
  return responses.response_invalid()

  # Access granted:
  return responses.response_allow(req=request_body)

  # Access denied:
  return responses.response_deny(req=response_body, msg="Reason to deny")
  
  # ...
```
