import sys
import traceback
import os
import re

import flask
import prometheus_client

from webhook.request_helper import responses
from webhook.request_helper import validate

bp = flask.Blueprint("namespace-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_NAMESPACE = prometheus_client.Counter(
    'webhook_namespace_validation_total',
    'The total number of namespace validation requests')
DENIED_NAMESPACE = prometheus_client.Counter(
    'webhook_namespace_validation_denied',
    'The total number of namespace validation requests denied')

# Use this with .match, which has an implicit start anchor (^)
PRIV_NS_RE = re.compile('|'.join(
    [
        'kube-.*',
        'openshift.*',
        'ops-health-monitoring$',
        'management-infra$',
        'default$',
        'logging$',
        'sre-app-check$',
        'redhat-.*',
    ]
))


@bp.route('/namespace-validation', methods=['POST'])
def handle_request():
    # inc total namespace counter
    TOTAL_NAMESPACE.inc()
    debug = os.getenv("DEBUG_NAMESPACE_VALIDATION", "False")
    debug = (debug == "True")

    if debug:
        print("REQUEST BODY => {}".format(flask.request.json))

    valid = True
    try:
        valid = validate.validate_request_structure(flask.request.json)
    except Exception:
        valid = False

    if not valid:
        # inc denied namespace counter
        DENIED_NAMESPACE.inc()
        return responses.response_invalid()

    try:
        body_dict = flask.request.json['request']
        requester_group_memberships = body_dict['userInfo']['groups']
        if "dedicated-admins" in requester_group_memberships:
            requested_ns = body_dict['namespace']
            # match will return a match object if the namespace matches the
            # regex, or None if the namespace doesn't match the regex.
            if PRIV_NS_RE.match(requested_ns) is not None:
                return responses.response_deny(
                    req=body_dict,
                    msg="You cannot update the privileged namespace {}."
                        .format(requested_ns))
            else:
                return responses.response_allow(req=body_dict)
        else:
            return responses.response_allow(req=body_dict)
    except Exception:
        print("Exception:")
        print("-" * 60)
        traceback.print_exc(file=sys.stdout)
        return responses.response_invalid()
