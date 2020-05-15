import unittest
import json

from webhook import subscription_validation


def create_request(namespace, groups):
    class FakeRequest(object):
        json = {
            "request": {
                "uid": "testuser",
                "userInfo": {
                    "username": "testuser",
                    "groups": groups,
                },
                "object": {
                    "spec": {
                        "sourceNamespace": namespace
                    }
                }
            }
        }

    return FakeRequest()


class TestSubscriptionValidation(unittest.TestCase):
    VALID_NAMESPACES = (
        "openshift-marketplace",
    )

    INVALID_NAMESPACES = (
        "kube-namespace",
        "redhat-example",
        "openshift",
        "openshift-test",
        "test-ns1",
        "default",
    )

    PRIVILEGED_GROUPS = (
        # These are tuples so they're immutable, forcing the test case to
        # duplicate in order to change them. Otherwise we have potential
        # collisions among test cases.
        # Note that code currently only denies if user is in dedicated-admin
        # group and trying to manage subscriptions in a namespace other than
        # openshift-marketplace - this will likely need to be changed in the
        # future to prevent other "non-privileged" groups from managing
        # subscriptions in namespaces besides openshift-marketplace.
        # For now, group "test-group" is considered privileged because it is
        # not specifically the "dedicated-admins" group.
        ("osd-sre-admins"),
        ("osd-sre-cluster-admins"),
        ("test-group"),
    )

    NON_PRIVILEGED_GROUPS = (
        # These are tuples so they're immutable, forcing the test case to
        # duplicate in order to change them. Otherwise we have potential
        # collisions among test cases.
        ("dedicated-admins"),
    )

    def runtest(self, namespace, groups, expect):
        # Make test failures easier to identify
        failmsg = "expect={}, namespace={}, groups={}".format(
            expect, namespace, groups)
        request = create_request(namespace, groups)
        response = subscription_validation.get_response(request)
        response = json.loads(response)['response']
        self.assertEqual(expect, response['allowed'], failmsg)
        # On DENY, validate the status message
        if not expect:
            self.assertEqual(
                "You cannot manage Subscriptions that target {}.".format(
                    namespace),
                response['status']['message'],
                failmsg)

    def test_allow_non_priv(self):
        # Users in non-privileged groups are allowed to manage subscriptions
        # in VALID_NAMESPACES
        for ns in self.VALID_NAMESPACES:
            for group in self.NON_PRIVILEGED_GROUPS:
                self.runtest(ns, group, True)

    def test_allow_priv(self):
        # Users in privileged groups are allowed to manage subscriptions
        # in all namespaces
        for ns in self.VALID_NAMESPACES + self.INVALID_NAMESPACES:
            for group in self.PRIVILEGED_GROUPS:
                self.runtest(ns, group, True)

    def test_deny(self):
        # In order to see denial, user in non-privileged group must attempt
        # to manage subscriptions in invalid namespaces
        for ns in self.INVALID_NAMESPACES:
            for group in self.NON_PRIVILEGED_GROUPS:
                self.runtest(ns, group, False)

    def test_invalid(self):
        # Validate the exception path
        request = create_request('foo', [])
        # This will trigger a KeyError when get_response tries to access the
        # 'userInfo'
        del request.json['request']['userInfo']
        response = subscription_validation.get_response(request)
        self.assertEqual(
            "Invalid request",
            json.loads(response)['response']['status']['message'])
