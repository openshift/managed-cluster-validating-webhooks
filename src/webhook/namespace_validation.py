from flask import request, Blueprint, Response
import sys, traceback
import json
import os
import prometheus_client
import re
from prometheus_client import Counter
from prometheus_client.core import CollectorRegistry

from webhook.request_helper import validate, responses

bp = Blueprint("namespace-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_NAMESPACE = Counter('webhook_namespace_validation_total', 'The total number of namespace validation requests')
DENIED_NAMESPACE = Counter('webhook_namespace_validation_denied', 'The total number of namespace validation requests denied')

@bp.route('/namespace-validation', methods=['POST'])
def handle_request():
  # inc total namespace counter
  TOTAL_NAMESPACE.inc()
  debug = os.getenv("DEBUG_NAMESPACE_VALIDATION", "False")
  debug = (debug == "True")

  if debug:
    print("REQUEST BODY => {}".format(request.json))

  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except Exception:
    valid = False

  if not valid:
    # inc denied namespace counter
    DENIED_NAMESPACE.inc()
    return responses.response_invalid()
  
  try:
    body_dict = request.json['request']
    requester_group_memberships = body_dict['userInfo']['groups']
    if "dedicated-admins" in requester_group_memberships:
      requested_ns = body_dict['namespace']
      privileged_namespace_re = '(^kube-.*|^openshift.*|^ops-health-monitoring$|^management-infra$|^default$|^logging$|^sre-app-check$|^redhat-.*)'
      # match will return a match object if the namespace matches the regex, or None if the namespace doesn't match the regex
      if re.match(privileged_namespace_re, requested_ns) is not None:
        return responses.response_deny(req=body_dict, msg="You cannot update the privileged namespace {}.".format(requested_ns))
      else:
        return responses.response_allow(req=body_dict)
    else:
      return responses.response_allow(req=body_dict)
  except Exception:
    print("Exception:")
    print("-"*60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()
