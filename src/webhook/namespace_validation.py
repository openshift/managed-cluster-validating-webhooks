from flask import request, Blueprint
import sys, traceback
import os
import re
from prometheus_client import Counter

from webhook.request_helper import validate, responses

bp = Blueprint("namespace-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_NAMESPACE = Counter('webhook_namespace_validation_total', 'The total number of namespace validation requests')
DENIED_NAMESPACE = Counter('webhook_namespace_validation_denied', 'The total number of namespace validation requests denied')


@bp.route('/namespace-validation', methods=['POST'])
def handle_request():
  # inc total namespace counter
  TOTAL_NAMESPACE.inc()
  debug = os.getenv("DEBUG_NAMESPACE_VALIDATION", "False")
  debug = (debug == "True")

  if debug:
    print("REQUEST BODY => {}".format(request.json))

  valid = True
  try:
    valid = validate.validate_request_structure(request.json)
  except Exception:
    valid = False

  if not valid:
    # inc denied namespace counter
    DENIED_NAMESPACE.inc()
    return responses.response_invalid()
  
  return get_response(request, debug)


def get_response(req, debug=False):
  try:
    body_dict = req.json['request']
    requester_group_memberships = []
    if 'userInfo' in body_dict:
      userinfo = body_dict['userInfo']
      if 'groups' in body_dict['userInfo']:
        requester_group_memberships = body_dict['userInfo']['groups']
    else:
      return responses.response_invalid()

    privileged_namespace_re = '(^kube.*|^openshift.*|^default$|^redhat.*)'
    requested_ns = body_dict['namespace']
    cluster_admin_users = ["kube:admin", "system:admin"]

    # check to see if requester is a serviceAccount in a privileged NS
    # if so, SA can edit any namespace
    # re.match will return a match object if the namespace matches the regex,
    # or None if the string doesn't match the regex
    privileged_serviceaccount_re = '^system:serviceaccounts:(kube.*|openshift.*|default|redhat.*)'
    for group in requester_group_memberships:
      if re.match(privileged_serviceaccount_re, group) is not None:
        return responses.response_allow(req=body_dict)
      
    # check to see if user in layered-sre-cluster-admins group
    # if so, user can edit privileged namespaces matching '^redhat.*'
    if (re.match('^redhat.*', requested_ns) is not None and
        "layered-sre-cluster-admins" in requester_group_memberships):
      return responses.response_allow(req=body_dict)

    # check to see if the NS is privileged. if it is, we only want SRE,
    # kube:admin, and system:admin editing it
    if re.match(privileged_namespace_re, requested_ns) is not None:
      if ("osd-sre-admins" in requester_group_memberships or
          "osd-sre-cluster-admins" in requester_group_memberships or
          userinfo['username'] in cluster_admin_users):
        return responses.response_allow(req=body_dict)
      else:
        DENIED_NAMESPACE.inc()
        return responses.response_deny(req=body_dict, msg="You cannot update the privileged namespace {}.".format(requested_ns))

    # if we're here, the requested NS is not a privileged NS, and webhook can
    # allow RBAC to handle whether user is permitted to edit NS or not
    return responses.response_allow(req=body_dict)

  except Exception:
    print("Exception:")
    print("-" * 60)
    traceback.print_exc(file=sys.stdout)
    return responses.response_invalid()
