from flask import request, Blueprint, Response
import sys, traceback
import json
import os
import prometheus_client
from prometheus_client import Counter
from prometheus_client.core import CollectorRegistry

from webhook.request_helper import validate, responses

bp = Blueprint("regular-user-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
REGULAR_USER_DENIED = Counter('webhook_regular_user_denied', 'The total number of regular-user requests denied', labelnames=["request_kind","request_namespace","request_username","request_operation"])

@bp.route('/regular-user-validation', methods=['POST'])
def handle_request():
  debug = os.getenv("DEBUG_REGULAR_USER_DENIER", "False")
  debug = (debug == "True")

  if debug:
    print("REQUEST BODY => {}".format(request.json))

  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except Exception:
    valid = False

  if not valid:
    # inc denied counter
    REGULAR_USER_DENIED.labels(None,None,None,None).inc()
    return responses.response_invalid()
  
  try:
    # get the username and decide if it's a special user (SA, kube:admin, etc) or not.. 
    # deny any request if it's not a special user.  NOTE you cannot create users with a colon, using that as the check
    # reference: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request
    body_dict = request.json['request']
    username = body_dict['userInfo']['username']
    if not ":" in username:
      kind = body_dict['object']['kind']
      operation = body_dict['operation']
      namespace = None
      if 'namespace' in body_dict:
        namespace = body_dict['namespace']
      REGULAR_USER_DENIED.labels(kind,namespace,username,operation).inc()
      return responses.response_deny(req=body_dict, msg="Regular user '{}' cannot {} kind '{}'.".format(username, operation, kind))
    else:
      return responses.response_allow(req=body_dict)
  except Exception:
    print("Exception:")
    print("-"*60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()