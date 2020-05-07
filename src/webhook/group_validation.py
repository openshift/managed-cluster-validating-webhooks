from flask import request, Blueprint
import sys, traceback
import os
import re
from prometheus_client import Counter
from webhook.request_helper import validate, responses

bp = Blueprint("group-webhook", __name__)

DEBUG = os.getenv("DEBUG_GROUP_VALIDATION", "False")

# define what we track, declare Counter, how many times this route is accessed
TOTAL_GROUP = Counter('webhook_group_validation_total', 'The total number of group validation requests')
DENIED_GROUP = Counter('webhook_group_validation_denied', 'The total number of group validation requests denied')

admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP", "osd-sre-admins,osd-sre-cluster-admins")

admin_groups = admin_group.split(",")

# groups that cannot be edited by non-admins
protected_group_regex = os.getenv("GROUP_VALIDATION_PROTECTED_GROUP_REGEX", "(^osd-sre.*|^dedicated-admins$|^cluster-admins$|^layered-cs-sre-admins$)")

exclusive_group_prefixes = os.getenv("GROUP_VALIDATION_EXCLUSIVE_GROUP_PREFIXES", "").split(",")


def log_debug(msg):
  if DEBUG:
    print(msg)


def log(msg):
  print(msg)


@bp.route('/group-validation', methods=['POST'])
def handle_request():
  # inc total group counter
  TOTAL_GROUP.inc()

  log_debug("REQUEST BODY => {}".format(request.json))

  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except:
    valid = False

  if not valid:
    # inc denied group counter
    DENIED_GROUP.inc()
    return responses.response_invalid()

  return get_response(
    request, 
    exclusive_group_prefixes=exclusive_group_prefixes
  )


def get_response(req, exclusive_group_prefixes=[]):
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

    if user_name in ("kube:admin", "system:admin"):
      # kube/system admin can do anything
      log_debug("Performing action: {} in {} group for {}".format(body_dict['operation'], group_name, userinfo['username']))
      return responses.response_allow(req=body_dict)

    if re.match(protected_group_regex, group_name) is not None:
      # attempted operation on a protected group
      log_debug("Performing action: {} in {} group".format(body_dict['operation'], group_name))
    
      deny_msg = "User not authorized to {} group {}".format(
          body_dict['operation'], group_name)

      exclusive_prefix = match_group_prefix(
        group_name, 
        exclusive_group_prefixes
      )
      user_groups_prefixes = match_group_list_prefix(
          user_groups, [exclusive_prefix])    

      if len(set(user_groups) & set(admin_groups)) > 0:
        
        if exclusive_prefix and not user_groups_prefixes:
          log_debug(('Operations on group "{}" are exclusive only to users in '
                   'groups with prefix "{}"').format(group_name, exclusive_prefix))
          response_body = responses.response_deny(req=body_dict, msg=deny_msg)
        else:
          # user is a member of admin groups, this is allowed
          response_body = responses.response_allow(
          req=body_dict, 
          msg="{} group {}".format(body_dict['operation'], group_name)
      )
      else:
        # user is NOT a member of admin groups, this is denied
        response_body = responses.response_deny(req=body_dict, msg=deny_msg)
    else:
      # was not a protected group, so we can let it through
      response_body = responses.response_allow(req=body_dict)
    
    log_debug("Response body => {}".format(response_body))
    return response_body
  except Exception:
    log("Exception when trying to access attributes. Request body: {}".format(req.json))
    log("Backtrace:")
    log("-" * 60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()


def match_group_prefix(group, group_prefixes):
  """Returns the first match of a group prefix in a list of group prefixes"""
  for prefix in group_prefixes:
    if prefix and len(prefix) and group.startswith(prefix):
      return prefix


def match_group_list_prefix(group_list, group_prefixes):
  """Returns a list of matched group prefixes from a list of group prefixes"""
  prefixes = []
  for group in group_list:
    prefix = match_group_prefix(group, group_prefixes)
    if prefix:
      prefixes.append(prefix)
  return prefixes
  