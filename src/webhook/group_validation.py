from flask import request, Blueprint
import json
import os

from webhook.request_helper import validate, responses

bp = Blueprint("webhook", __name__)

group_prefix = os.getenv("GROUP_VALIDATION_PREFIX")
admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP")

configok = True

if group_prefix is None:
  print("Please specify the group prefix with GROUP_VALIDATION_PREFIX environment variable. Refusing to expose /group-validation webhook.")
  configok = False

if admin_group is None:
  print("Please specify the admin group with the GROUP_VALIDATION_ADMIN_GROUP environment variable. Refusing to expose /group-validation webhook.")
  configok = False

if configok:
  @bp.route('/group-validation', methods=('GET','POST'))
  def handle_request():
    debug = os.getenv("DEBUG_GROUP_VALIDATION", "False")
    debug = (debug == "True")

    valid = True
    try:
      valid = validate.validate_request_structure(request.json)
    except:
      # if anything goes wrong, it's not valid.
      valid = False

    if not valid:
      return responses.response_invalid()

    body_dict = request.json['request']
    group_name = body_dict['object']['metadata']['name']
    userinfo = body_dict['userInfo']

    if debug:
      print("REQUEST BODY => {}".format(body_dict))
      print("Performing action: {} in {} group".format(body_dict['operation'],group_name))

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