# Managed Cluster Validating Webhooks

A Flask app designed to act as a webhook admission controller for OpenShift.

Presently there is a single webhook, [group-validation](#group_validation), which is provided via `/group-validation` endpoint.

## Group Validation

Configuration for this webhook is provided by environment variables:

* `GROUP_VALIDATION_PREFIX` - Group prefix to apply the webhook, such as `osd-` to apply to `CREATE`, `UPDATE`, `DELETE` operations on groups starting with `osd-`.
* `GROUP_VALIDATION_ADMIN_GROUP` - Admin group, which the requestor must be a member in order to have access granted.
* `DEBUG_GROUP_VALIDATION` - Debug the webhook? Set to `True` to enable, all other values (including absent) disable.

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
