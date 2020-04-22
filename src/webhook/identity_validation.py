from flask import request, Blueprint
import sys
import traceback
import os
from prometheus_client import Counter
from webhook.request_helper import validate, responses

bp = Blueprint("identity-webhook", __name__)

# define what we track, declare Counter, how many times this route is accessed
TOTAL_IDENTITY = Counter('webhook_identity_validation_total',
                         'The total number of identity validation requests')
DENIED_IDENTITY = Counter('webhook_identity_validation_denied',
                          'The total number of identity validation requests denied')

identity_provider = os.getenv("IDENTITY_PROVIDER", "OpenShift_SRE")

admin_group = os.getenv("GROUP_VALIDATION_ADMIN_GROUP",
                        "osd-sre-admins,osd-sre-cluster-admins")
admin_groups = admin_group.split(",")


@bp.route('/identity-validation', methods=['POST'])
def handle_request():
    # inc total identity counter
    TOTAL_IDENTITY.inc()
    debug = os.getenv("DEBUG_IDENTITY_VALIDATION", "False")
    debug = (debug == "True")

    if debug:
        print("REQUEST BODY => {}".format(request.json))

    valid = True
    try:
        valid = validate.validate_request_structure(request.json)
    except:
        valid = False

    if not valid:
        # inc denied identity counter
        DENIED_IDENTITY.inc()
        return responses.response_invalid()
    return get_response(request, debug)


def get_response(request, debug=False):
    try:
        body_dict = request.json['request']
        # If trying to delete a user, must get user name from oldObject instead of object
        if body_dict['object'] is None:
            identity_name = body_dict['oldObject']['metadata']['name']
            provider_name = body_dict['oldObject']['providerName']
        else:
            identity_name = body_dict['object']['metadata']['name']
            provider_name = body_dict['object']['providerName']
        userinfo = body_dict['userInfo']
        if userinfo['username'] in ("kube:admin", "system:admin", "system:serviceaccount:openshift-authentication:oauth-openshift"):
            # kube/system admin can do anything
            if debug:
                print("Performing action: {} on identity {} by {}".format(
                    body_dict['operation'], identity_name, userinfo['username']))
            return responses.response_allow(req=body_dict)

        if provider_name == identity_provider:
            if debug:
                print("Performing action: {} on {} identity".format(
                    body_dict['operation'], identity_name))
            if len(set(userinfo['groups']) & set(admin_groups)) > 0:
                response_body = responses.response_allow(
                    req=body_dict, msg="{} identity {}".format(body_dict['operation'], identity_name))
            else:
                deny_msg = "User not authorized to {} identity {}".format(
                    body_dict['operation'], identity_name)
                response_body = responses.response_deny(
                    req=body_dict, msg=deny_msg)
                DENIED_IDENTITY.inc()
        else:
            response_body = responses.response_allow(req=body_dict)
        if debug:
            print("Response body => {}".format(response_body))
        return response_body
    except Exception:
        print("Exception when trying to access attributes. Request body: {}".format(
            request.json))
        print("Backtrace:")
        print("-" * 60)
        traceback.print_exc(file=sys.stdout)
        return responses.response_invalid()
