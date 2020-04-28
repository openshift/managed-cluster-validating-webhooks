import unittest
import json

from webhook.identity_validation import get_response

ADMIN_GROUPS = ["osd-sre-admins"]


def create_request(username, groups, identityName, providerName):
    class FakeRequest(object):
        def __init__(self):
            self.json = {
                "request": {
                    "uid": "testuser",
                    "operation": "UPDATE",
                    "userInfo": {"groups": groups, "username": username,},
                    "object": {
                        "kind": "Identity",
                        "metadata": {"name": identityName},
                        "providerName": providerName,
                    },
                }
            }

        def __getitem__(self, item):
            return getattr(self, item)

    return FakeRequest()


class TestIdentityValidation(unittest.TestCase):
    def runtests(self, username, testGroups, identityName, providerName):
        request = create_request(username, testGroups, identityName, providerName)

        response = json.loads(get_response(request, debug=False))
        return response

    # oauth ServiceAccount can update redhat user identity
    def test_oauth_sa(self):
        response = self.runtests(
            "system:serviceaccount:openshift-authentication:oauth-openshift",
            "",
            "OpenShift_SRE:test",
            "OpenShift_SRE",
        )
        self.assertTrue(response["response"]["allowed"])

    # system:admin can update redhat user identity
    def test_system_admin(self):
        response = self.runtests(
            "system:admin", "", "OpenShift_SRE:test", "OpenShift_SRE"
        )
        self.assertTrue(response["response"]["allowed"])

    # kube:admin can update redhat user identity
    def test_kube_admin(self):
        response = self.runtests(
            "kube:admin", "", "OpenShift_SRE:test", "OpenShift_SRE"
        )
        self.assertTrue(response["response"]["allowed"])

    # users in sre admin groups can update redhat user identity
    def test_sre_groups(self):
        response = self.runtests(
            "test@redhat.com", ADMIN_GROUPS, "OpenShift_SRE:test", "OpenShift_SRE"
        )
        self.assertTrue(response["response"]["allowed"])

    # dedicated-admins can update custom user identity
    def test_ded_admins_custom_user(self):
        response = self.runtests(
            "test@customdomain", "dedicated-admins", "CUSTOM:test", "CUSTOM"
        )
        self.assertTrue(response["response"]["allowed"])

    # dedicated-admins cannot update redhat user identity
    def test_ded_admins_redhat_user(self):
        response = self.runtests(
            "customer@custom", "dedicated-admins", "OpenShift_SRE:test", "OpenShift_SRE"
        )
        self.assertFalse(response["response"]["allowed"])

    # users in sre admin groups can update redhat user identity
    def test_sre_update_custom_user(self):
        response = self.runtests(
            "test@redhat.com", ADMIN_GROUPS, "CUSTOM:test", "CUSTOM"
        )
        self.assertTrue(response["response"]["allowed"])
