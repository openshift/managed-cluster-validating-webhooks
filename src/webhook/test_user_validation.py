import unittest
import json

from webhook.user_validation import get_response

ADMIN_GROUPS = ["osd-sre-admins"]


def create_request(username, groups, objectName):
    class FakeRequest(object):
        def __init__(self):
            self.json = {
                "request": {
                    "uid": "testuser",
                    "operation": "UPDATE",
                    "userInfo": {"groups": groups, "username": username,},
                    "object": {"kind": "User", "metadata": {"name": objectName,}},
                }
            }

        def __getitem__(self, item):
            return getattr(self, item)

    return FakeRequest()


class TestUserValidation(unittest.TestCase):
    def runtests(self, username, testGroups, objectName):
        request = create_request(username, testGroups, objectName)

        response = json.loads(get_response(request, debug=False))
        return response

    # oauth ServiceAccount can update redhat users
    def test_oauth_sa(self):
        response = self.runtests(
            "system:serviceaccount:openshift-authentication:oauth-openshift",
            "",
            "test@redhat.com",
        )
        self.assertTrue(response["response"]["allowed"])

    # system:admin can update redhat users
    def test_system_admin(self):
        response = self.runtests("system:admin", "", "test@redhat.com")
        self.assertTrue(response["response"]["allowed"])

    # kube:admin can update redhat users
    def test_kube_admin(self):
        response = self.runtests("kube:admin", "", "test@redhat.com")
        self.assertTrue(response["response"]["allowed"])

    # users in sre admin groups can update redhat users
    def test_sre_groups(self):
        response = self.runtests("test@redhat.com", ADMIN_GROUPS, "test@redhat.com")
        self.assertTrue(response["response"]["allowed"])

    # dedicated-admins can update custom users
    def test_ded_admins_custom_user(self):
        response = self.runtests(
            "test@customdomain", "dedicated-admins", "test1@customdomain"
        )
        self.assertTrue(response["response"]["allowed"])

    # dedicated-admins cannot update redhat users
    def test_ded_admins_redhat_user(self):
        response = self.runtests(
            "customer@custom", "dedicated-admins", "test@redhat.com"
        )
        self.assertFalse(response["response"]["allowed"])

    # users in sre admin groups can update redhat user
    def test_sre_update_custom_user(self):
        response = self.runtests("test@redhat.com", ADMIN_GROUPS, "test@customdomain")
        self.assertTrue(response["response"]["allowed"])
