import json
import os


def response_base(req, allowed, msg=""):
    body = {
        "apiVersion": "admission.k8s.io/v1beta1",
        "kind": "AdmissionReview",
        "response": {"uid": req["uid"], "allowed": allowed, "status": {"message": msg}},
    }
    return json.dumps(body)


def response_allow(req, msg="Allowed resource for this cluster"):
    print(
        "[pid={}] Allowing admission {}: {}".format(
            os.getpid(), req["userInfo"]["username"], msg
        )
    )
    return response_base(req=req, allowed=True, msg="Access granted")


def response_deny(req, msg="Prohibited resource for this cluster"):
    print(
        "[pid={}] Denying admission {}: {}".format(
            os.getpid(), req["userInfo"]["username"], msg
        )
    )
    return response_base(req=req, allowed=False, msg=msg)


def response_invalid():
    return response_base({"uid": ""}, allowed=False, msg="Invalid request")
