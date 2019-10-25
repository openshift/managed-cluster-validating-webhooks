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
