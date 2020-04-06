from flask import request, Blueprint
import sys, traceback
import os
from prometheus_client import Counter
from webhook.request_helper import validate, responses

bp = Blueprint("group-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_GROUP = Counter('webhook_group_validation_total', 'The total number of group validation requests')
DENIED_GROUP = Counter('webhook_group_validation_denied', 'The total number of group validation requests denied')

group_prefix = os.getenv("GROUP_VALIDATION_PREFIX", "osd-sre-")
admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP", "osd-sre-admins,osd-sre-cluster-admins")

admin_groups = admin_group.split(",")


@bp.route('/group-validation', methods=['POST'])
def handle_request():
  # inc total group counter
  TOTAL_GROUP.inc()
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
    # inc denied group counter
    DENIED_GROUP.inc()
    return responses.response_invalid()

  try:
    body_dict = request.json['request']
    # If trying to delete a group, must get group name from oldObject instead of object
    if body_dict['object'] is None:
      group_name = body_dict['oldObject']['metadata']['name']
    else:
      group_name = body_dict['object']['metadata']['name']
    userinfo = body_dict['userInfo']
    if userinfo['username'] in ("kube:admin", "system:admin"):
      # kube/system admin can do anything
      if debug:
        print("Performing action: {} in {} group for {}".format(body_dict['operation'], group_name, userinfo['username']))
      return responses.response_allow(req=body_dict)
    if group_name.startswith(group_prefix):
      if debug:
        print("Performing action: {} in {} group".format(body_dict['operation'], group_name))
      if len(set(userinfo['groups']) & set(admin_groups)) > 0:
        response_body = responses.response_allow(req=body_dict, msg="{} group {}".format(body_dict['operation'], group_name))
      else:
        deny_msg = "User not authorized to {} group {}".format(body_dict['operation'], group_name)
        response_body = responses.response_deny(req=body_dict, msg=deny_msg)
    else:
      response_body = responses.response_allow(req=body_dict)
    if debug:
      print("Response body => {}".format(response_body))
    return response_body
  except Exception:
    print("Exception when trying to access attributes. Request body: {}".format(request.json))
    print("Backtrace:")
    print("-" * 60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()
