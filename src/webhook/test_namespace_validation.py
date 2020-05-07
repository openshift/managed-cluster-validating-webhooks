import unittest
import json

from webhook import namespace_validation


def create_request(namespace, groups, userName):
    class FakeRequest(object):
        json = {
            "request": {
                "uid": "testuser",
                "userInfo": {
                    "username": userName,
                    "groups": groups,
                },
                "namespace": namespace,
            }
        }

    return FakeRequest()


class TestNamespaceValidation(unittest.TestCase):
    PRIVILEGED_NAMESPACES = (
        "kube-admin",
        "kube-foo",
        "openshift",
        "openshifter",
        "openshift-foo",
        "default",
    )

    REDHAT_NAMESPACES = (
        "redhat-user",
        "redhat-wow",
        "redhatuser",
    )

    NONPRIV_NAMESPACES = (
        "kudeadmin",
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
    )

    PRIVILEGED_USERS = (
        "kube:admin",
        "system:admin",
    )

    NON_PRIVILEGED_USERS = (
        "random_user",
        "employee",
        "employee@redhat.com",
        "test-user",
    )

    def runtest(self, namespace, groups, userName, expect):
        # Make test failures easier to identify
        failmsg = "expect={}, namespace={}, groups={}, user={}".format(
            expect, namespace, groups, userName)
        request = create_request(namespace, groups, userName)
        response = namespace_validation.get_response(request)
        response = json.loads(response)['response']
        self.assertEqual(expect, response['allowed'], failmsg)
        # On DENY, validate the status message
        if not expect:
            self.assertEqual(
                "You cannot update the privileged namespace {}.".format(
                    namespace),
                response['status']['message'],
                failmsg)

    def test_deny(self):
        # layered-cs-sre-admins should not have access to any privledged namespaces except ones starting with 'redhat'
        # dedicated-admins should not have access to any privledged namespaces
        for ns in self.PRIVILEGED_NAMESPACES:
            for user in self.NON_PRIVILEGED_USERS:
                groups = ('layered-cs-sre-admins',)
                self.runtest(ns, groups, user, False)
                groups = ('dedicated-admins',)
                self.runtest(ns, groups, user, False)
                groups = ('random-test-group',)
                self.runtest(ns, groups, user, False)
        for ns in self.REDHAT_NAMESPACES:
            for user in self.NON_PRIVILEGED_USERS:
                groups = ('dedicated-admins',)
                self.runtest(ns, groups, user, False)
                groups = ('random-test-group',)
                self.runtest(ns, groups, user, False)

    def test_allow_group(self):
        # user in osd-sre-admins group can edit non-privileged NS
        # user in osd-sre-admins group can edit privileged NS
        for ns in self.PRIVILEGED_NAMESPACES + self.NONPRIV_NAMESPACES + self.REDHAT_NAMESPACES:
            for user in self.NON_PRIVILEGED_USERS:
                groups = ('osd-sre-cluster-admins',)
                self.runtest(ns, groups, user, True)
                groups = ('osd-sre-admins',)
                self.runtest(ns, groups, user, True)

    def test_allow_layered_admins(self):
        # user in layered-sre-cluster-admins group can edit non-privileged NS
        for ns in self.NONPRIV_NAMESPACES + self.REDHAT_NAMESPACES:
            for user in self.NON_PRIVILEGED_USERS:
                groups = ('layered-sre-cluster-admins',)
                self.runtest(ns, groups, user, True)

    def test_priv_users(self):
        # all privileged users (kube/system:admin) can edit any privileged or
        # non-privileged NS
        for user in self.PRIVILEGED_USERS:
            for ns in self.PRIVILEGED_NAMESPACES + self.NONPRIV_NAMESPACES + self.REDHAT_NAMESPACES:
                groups = ('random-test-group',)
                self.runtest(ns, groups, user, True)

    def test_allow_ns(self):
        # Nonprivileged namespaces always ALLOW, even if the group list
        # contains 'dedicated-admins'.
        for ns in self.NONPRIV_NAMESPACES:
            for user in self.NON_PRIVILEGED_USERS:
                groups = ('dedicated-admins',)
                self.runtest(ns, groups, user, True)
                groups = ('random-test-group',)
                self.runtest(ns, groups, user, True)

    def test_invalid(self):
        # Validate the exception path
        request = create_request('foo', [], [])
        # This will trigger a KeyError when get_response tries to access the
        # 'userInfo'
        del request.json['request']['userInfo']
        response = namespace_validation.get_response(request)
        self.assertEqual(
            "Invalid request",
            json.loads(response)['response']['status']['message'])
