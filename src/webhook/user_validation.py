from flask import request, Blueprint
import sys, traceback
import os
from prometheus_client import Counter
from webhook.request_helper import validate, responses

bp = Blueprint("user-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_USER = Counter('webhook_user_validation_total', 'The total number of user validation requests')
DENIED_USER = Counter('webhook_user_validation_denied', 'The total number of user validation requests denied')

user_suffix = "@redhat.com"

admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP", "osd-sre-admins,osd-sre-cluster-admins")
admin_groups = admin_group.split(",")


@bp.route('/user-validation', methods=['POST'])
def handle_request():
  # inc total user counter
  TOTAL_USER.inc()
  debug = os.getenv("DEBUG_USER_VALIDATION", "False")
  debug = (debug == "True")

  if debug:
    print("REQUEST BODY => {}".format(request.json))

  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except:
    valid = False

  if not valid:
    # inc denied user counter
    DENIED_USER.inc()
    return responses.response_invalid()

  try:
    body_dict = request.json['request']
    # If trying to delete a user, must get user name from oldObject instead of object
    if body_dict['object'] is None:
      user_name = body_dict['oldObject']['metadata']['name']
    else:
      user_name = body_dict['object']['metadata']['name']
    userinfo = body_dict['userInfo']
    if userinfo['username'] in ("kube:admin", "system:admin", "system:serviceaccount:openshift-authentication:oauth-openshift"):
      # kube/system admin, oauth service accounts can do anything
      if debug:
        print("Performing action: {} on user {} by {}".format(body_dict['operation'], user_name, userinfo['username']))
      return responses.response_allow(req=body_dict)
    if user_name.endswith(user_suffix):
      if debug:
        print("Performing action: {} on {} user".format(body_dict['operation'], user_name))
      if len(set(userinfo['groups']) & set(admin_groups)) > 0:
        response_body = responses.response_allow(req=body_dict, msg="{} user {}".format(body_dict['operation'], user_name))
      else:
        deny_msg = "User not authorized to {} user {}".format(body_dict['operation'], user_name)
        response_body = responses.response_deny(req=body_dict, msg=deny_msg)
        DENIED_USER.inc()
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
