import unittest
import json

from webhook import namespace_validation


PRIVILEGED_NAMESPACES = (
    "kube-admin",
    "kube-foo",
    "kube-",
    "openshift",
    "openshifter",
    "openshift-foo",
    "ops-health-monitoring",
    "management-infra",
    "default",
    "logging",
    "sre-app-check",
    "redhat-user",
    "redhat-",
    "redhat-wow",
)

NONPRIV_NAMESPACES = (
    "kubeadmin",
    "mykube-admin",
    "open-shift",
    "oopenshift",
    "ops-health-monitoring-foo",
    "the-ops-health-monitoring",
    "management-infra1",
    "mymanagement-infra",
    "default-user",
    "adefault",
    "logger",
    "some-logging",
    "redhatuser",
)

# None of these contain 'dedicated-admins', so will result in ALLOW unless
# it's added.
GROUP_LISTS = (
    # These are tuples so they're immutable, forcing the test case to
    # duplicate in order to change them. Otherwise we have potential
    # collisions among test cases.
    (),
    ("cluster-admins",),
    ("osd-sre-admins",),
    ("layered-cs-sre-admins",),
)


def create_request(namespace, groups):
    class FakeRequest(object):
        json = {
            "request": {
                "uid": "testuser",
                "userInfo": {"username": "me", "groups": groups,},
                "namespace": namespace,
            }
        }

    return FakeRequest()


class TestNamespaceValidation(unittest.TestCase):
    def runtest(self, namespace, groups, expect):
        # Make test failures easier to identify
        failmsg = "expect={}, namespace={}, groups={}".format(expect, namespace, groups)
        request = create_request(namespace, groups)
        response = namespace_validation.get_response(request)
        response = json.loads(response)["response"]
        self.assertEqual(expect, response["allowed"], failmsg)
        # On DENY, validate the status message
        if not expect:
            self.assertEqual(
                "You cannot update the privileged namespace {}.".format(namespace),
                response["status"]["message"],
                failmsg,
            )

    def test_deny(self):
        # In order to get DENYs, we must have *both* a privileged namespace
        # *and* the 'dedicated-admins' group.
        for ns in PRIVILEGED_NAMESPACES:
            for gl in GROUP_LISTS:
                # Always include dedicated-admins
                groups = gl + ("dedicated-admins",)
                self.runtest(ns, groups, False)

    def test_allow_group(self):
        # If the group list doesn't contain 'dedicated-admins', always ALLOW,
        # even if the namespace is privileged. (Really?)
        for ns in PRIVILEGED_NAMESPACES + NONPRIV_NAMESPACES:
            for gl in GROUP_LISTS:
                self.runtest(ns, gl, True)

    def test_allow_ns(self):
        # Nonprivileged namespaces always ALLOW, even if the group list
        # contains 'dedicated-admins'.
        for ns in NONPRIV_NAMESPACES:
            for gl in GROUP_LISTS:
                self.runtest(ns, gl, True)
                groups = gl + ("dedicated-admins",)
                self.runtest(ns, groups, True)

    def test_invalid(self):
        # Validate the exception path
        request = create_request("foo", [])
        # This will trigger a KeyError when get_response tries to access the
        # 'userInfo'
        del request.json["request"]["userInfo"]
        response = namespace_validation.get_response(request)
        self.assertEqual(
            "Invalid request", json.loads(response)["response"]["status"]["message"]
        )
