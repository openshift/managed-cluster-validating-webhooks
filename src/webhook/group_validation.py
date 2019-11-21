from flask import request, Blueprint
import sys, traceback
import json
import os

from webhook.request_helper import validate, responses

bp = Blueprint("group-webhook", __name__)

group_prefix = os.getenv("GROUP_VALIDATION_PREFIX", "osd-sre-")
admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP", "osd-sre-admins")

@bp.route('/group-validation', methods=['POST'])
def handle_request():
  debug = os.getenv("DEBUG_GROUP_VALIDATION", "False")
  debug = (debug == "True")

  if debug:
    print("REQUEST BODY => {}".format(request.json))

  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except:
    valid = False

  if not valid:
    return responses.response_invalid()

  try:
    body_dict = request.json['request']
    group_name = body_dict['object']['metadata']['name']
    userinfo = body_dict['userInfo']
    if group_name.startswith(group_prefix):
      if debug:
        print("Performing action: {} in {} group".format(body_dict['operation'],group_name))
      if admin_group in userinfo['groups']:
        response_body = responses.response_allow(req=body_dict,msg="{} group {}".format(body_dict['operation'], group_name))
      else:
        deny_msg = "User not authorized to {} group {}".format(body_dict['operation'],group_name)
        response_body = responses.response_deny(req=body_dict,msg=deny_msg)
    else:
      response_body = responses.response_allow(req=body_dict)
    if debug:
      print("Response body => {}".format(response_body))
    return response_body
  except Exception:
    print("Exception when trying to access attributes. Request body: {}".format(request.json))
    print("Backtrace:")
    print("-"*60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()
