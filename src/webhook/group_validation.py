from flask import request, Blueprint
import sys, traceback
import os
import re
from prometheus_client import Counter
from webhook.request_helper import validate, responses

bp = Blueprint("group-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_GROUP = Counter('webhook_group_validation_total', 'The total number of group validation requests')
DENIED_GROUP = Counter('webhook_group_validation_denied', 'The total number of group validation requests denied')

admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP", "osd-sre-admins,osd-sre-cluster-admins")

admin_groups = admin_group.split(",")

# groups that cannot be edited by non-admins
protected_group_regex = os.getenv("GROUP_VALIDATION_PROTECTED_GROUP_REGEX", "(^osd-sre.*|^dedicated-admins$|^cluster-admins$|^layered-cs-sre-admins$)")


@bp.route('/group-validation', methods=['POST'])
def handle_request():
  # inc total group counter
  TOTAL_GROUP.inc()
  debug = os.getenv("DEBUG_GROUP_VALIDATION", "False")
  debug = (debug == "True")

  if debug:
    print("REQUEST BODY => {}".format(request.json))

  return get_response(request, debug)


def get_response(req, debug=False):
  valid = True
  try:
    valid = validate.validate_request_structure(req.json)
  except:
    valid = False

  if not valid:
    # inc denied group counter
    DENIED_GROUP.inc()
    return responses.response_invalid()

  try:
    body_dict = req.json['request']
    # If trying to delete a group, must get group name from oldObject instead of object
    if body_dict['object'] is None:
      group_name = body_dict['oldObject']['metadata']['name']
    else:
      group_name = body_dict['object']['metadata']['name']
    
    userinfo = {}
    if 'userInfo' in body_dict:
      userinfo = body_dict['userInfo']
    user_groups = []
    if 'groups' in userinfo:
      user_groups = userinfo['groups']

    user_name = None
    if 'username' in userinfo:
      user_name = userinfo['username']

    if user_name is None:
      DENIED_GROUP.inc()
      return responses.response_invalid()

    if user_name in ("kube:admin", "system:admin"):
      # kube/system admin can do anything
      if debug:
        print("Performing action: {} in {} group for {}".format(body_dict['operation'], group_name, userinfo['username']))
      return responses.response_allow(req=body_dict)

    if re.match(protected_group_regex, group_name) is not None:
      # attempted operation on a protected group
      if debug:
        print("Performing action: {} in {} group".format(body_dict['operation'], group_name))
      if len(set(user_groups) & set(admin_groups)) > 0:
        # user is a member of admin groups, this is allowed
        response_body = responses.response_allow(req=body_dict, msg="{} group {}".format(body_dict['operation'], group_name))
      else:
        # user is NOT a member of admin groups, this is denied
        deny_msg = "User not authorized to {} group {}".format(body_dict['operation'], group_name)
        response_body = responses.response_deny(req=body_dict, msg=deny_msg)
    else:
      # was not a protected group, so we can let it through
      response_body = responses.response_allow(req=body_dict)
    if debug:
      print("Response body => {}".format(response_body))
    return response_body
  except Exception:
    print("Exception when trying to access attributes. Request body: {}".format(req.json))
    print("Backtrace:")
    print("-" * 60)
    traceback.print_exc(file=sys.stdout)
    DENIED_GROUP.inc()
    return responses.response_invalid()
