from flask import request, Blueprint, Response
import sys, traceback
import json
import os
import prometheus_client
from prometheus_client import Counter
from prometheus_client.core import CollectorRegistry

from webhook.request_helper import validate, responses

bp = Blueprint("subscription-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_SUBSCRIPTION = Counter('webhook_subscription_validation_total', 'The total number of subscription validation requests')
DENIED_SUBSCRIPTION = Counter('webhook_subscription_validation_denied', 'The total number of subscription validation requests denied')

valid_source_namespaces = os.getenv("SUBSCRIPTION_VALIDATION_NAMESPACES", "openshift-marketplace")
valid_source_namespaces = valid_source_namespaces.split(",")

@bp.route('/subscription-validation', methods=['POST'])
def handle_request():
  # inc total subscription counter
  TOTAL_SUBSCRIPTION.inc()
  debug = os.getenv("DEBUG_SUBSCRIPTION_VALIDATION", "False")
  debug = (debug == "True")

  if debug:
    print("REQUEST BODY => {}".format(request.json))

  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except Exception:
    valid = False

  if not valid:
    # inc denied subscription counter
    DENIED_SUBSCRIPTION.inc()
    return responses.response_invalid()
  
  try:
    body_dict = request.json['request']
    requester_group_memberships = body_dict['userInfo']['groups']
    if "dedicated-admins" in requester_group_memberships:
      if body_dict['object']['spec']['sourceNamespace'] not in valid_source_namespaces:
        return responses.response_deny(req=body_dict, msg="You cannot manage Subscriptions that target {}.".format(body_dict['object']['spec']['sourceNamespace']))
      else:
        return responses.response_allow(req=body_dict)
    else:
      return responses.response_allow(req=body_dict)
  except Exception:
    print("Exception:")
    print("-"*60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()