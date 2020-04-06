from flask import request, Blueprint
import sys, traceback
import os

from webhook.request_helper import validate, responses

bp = Blueprint("regular-user-webhook", __name__)

# the groups allowed to administer resources in cluster (i.e. exempt from this webhook)
admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP", "osd-sre-admins,osd-sre-cluster-admins")

admin_groups = admin_group.split(",")


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
  
  return get_response(request, debug)


def get_response(req, debug=False):
  if debug:
    print("REQUEST BODY => {}".format(req.json))

  try:
    body_dict = req.json['request']
    username = body_dict['userInfo']['username']

    if body_dict['object'] is None:
      group_name = body_dict['oldObject']['metadata']['name']
    else:
      group_name = body_dict['object']['metadata']['name']

    if is_request_allowed(username, group_name, admin_groups):
      return responses.response_allow(req=body_dict)
    else:
      kind = body_dict['object']['kind']
      operation = body_dict['operation']
      return responses.response_deny(req=body_dict, msg="Regular user '{}' cannot {} kind '{}'.".format(username, operation, kind))
  except Exception:
    print("Exception:")
    print("-" * 60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()


def is_request_allowed(username, groupname, admin_groupnames=()):
  """Decide if it's a special user (SA, kube:admin, etc) or not.

  reference: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request
  """
  # Explicitly unauthenticated
  if username == "system:unauthenticated":
      return False
  if groupname in admin_groupnames:
      return True
  if username.startswith("kube:") or username.startswith("system:"):
      return True
  # Deny anyone else
  return False
