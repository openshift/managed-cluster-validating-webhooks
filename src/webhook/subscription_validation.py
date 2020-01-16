from flask import request, Blueprint
import sys, traceback
import json
import os

from webhook.request_helper import validate, responses

bp = Blueprint("subscription-webhook", __name__)

valid_source_namespaces = os.getenv("SUBSCRIPTION_VALIDATION_NAMESPACES", "openshift-marketplace")

valid_source_namespaces = valid_source_namespaces.split(",")

@bp.route('/subscription-validation', methods=['POST'])
def handle_request():
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
