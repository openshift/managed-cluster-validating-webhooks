from flask import request, Blueprint, Response
import sys, traceback
import json
import os

from webhook.request_helper import validate, responses

bp = Blueprint("regular-user-webhook", __name__)

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
    return responses.response_invalid()
  
  try:
    # get the username and decide if it's a special user (SA, kube:admin, etc) or not.. 
    # deny any request if it's not a special user:  kube:*, system:* except system:unauthenticated
    # reference: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request
    body_dict = request.json['request']
    username = body_dict['userInfo']['username']
    if username == "system:unauthenticated" or (not username.startswith("kube:") and not username.startswith("system:")):
      kind = body_dict['object']['kind']
      operation = body_dict['operation']
      namespace = None
      if 'namespace' in body_dict:
        namespace = body_dict['namespace']
      return responses.response_deny(req=body_dict, msg="Regular user '{}' cannot {} kind '{}'.".format(username, operation, kind))
    else:
      return responses.response_allow(req=body_dict)
  except Exception:
    print("Exception:")
    print("-"*60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()