import unittest
import json

from webhook import group_validation

PRIVILEGED_USERS = (
    "kube:admin",
    "system:admin",
)

PRIVILEGED_GROUPS = (
    # These are tuples so they're immutable, forcing the test case to
    # duplicate in order to change them. Otherwise we have potential
    # collisions among test cases.
    ("osd-sre-admins"),
    ("osd-sre-cluster-admins"),
    ("osd-sre-test-group"),
)

NON_PRIVILEGED_USERS = (
    "random_user",
    "employee",
    "employee@redhat.com",
    "test-user",
)

NON_PRIVILEGED_GROUPS = (
    # These are tuples so they're immutable, forcing the test case to
    # duplicate in order to change them. Otherwise we have potential
    # collisions among test cases.
    ("test-group"),
    ("layered-cs-sre-admins"),
    ("random_group"),
    ("dedicated-admins"),
)


def create_request(user, memberGroups, editGroup):
    class FakeRequest(object):
        json = {
            "request": {
                "uid": "testuser",
                "userInfo": {
                    "username": user,
                    "groups": memberGroups,
                },
                "object": {
                    "metadata": {
                        "name": editGroup,
                    },
                },
                "operation": "update",
            }
        }

    return FakeRequest()

def create_delete_request(user, memberGroups, editGroup):
    class FakeRequest(object):
        json = {
            "request": {
                "uid": "testuser",
                "userInfo": {
                    "username": user,
                    "groups": memberGroups,
                },
                "object": None,
                "oldObject": {
                    "metadata": {
                        "name": editGroup,
                    },
                },
                "operation": "delete",
            }
        }

    return FakeRequest

class TestGroupValidation(unittest.TestCase):
    def runtest(self, user, memberGroups, editGroup, expect):
        failmsg = "expect={}, user={}, memberGroups={}, editGroup={}".format(
            expect, user, memberGroups, editGroup)
        request = create_request(user, memberGroups, editGroup)
        response = group_validation.get_response(request)
        response = json.loads(response)['response']
        self.assertEqual(expect, response['allowed'], failmsg)
        # On DENY, validate the status message
        if not expect:
            self.assertEqual(
                "User not authorized to update group {}".format(editGroup),
                response['status']['message'],
                failmsg)

    def rundeletetest(self, user, memberGroups, editGroup, expect):
        failmsg = "expect={}, user={}, memberGroups={}, editGroup={}".format(
            expect, user, memberGroups, editGroup)
        request = create_delete_request(user, memberGroups, editGroup)
        response = group_validation.get_response(request)
        response = json.loads(response)['response']
        self.assertEqual(expect, response['allowed'], failmsg)
        # On DENY, validate the status message
        if not expect:
            self.assertEqual(
                "User not authorized to delete group {}".format(editGroup),
                response['status']['message'],
                failmsg)

    def test_priv_user(self):
        # If the username is kube:admin or system:admin, always ALLOW,
        # regardless of whether memberGroups or editGroup is privileged 
        # or non-privileged
        for user in PRIVILEGED_USERS:
            for group in PRIVILEGED_GROUPS + NON_PRIVILEGED_GROUPS:
                self.runtest(user, PRIVILEGED_GROUPS, group, True)
                self.runtest(user, NON_PRIVILEGED_GROUPS, group, True)
                self.rundeletetest(user, PRIVILEGED_GROUPS, group, True)
                self.rundeletetest(user, NON_PRIVILEGED_GROUPS, group, True)

    def test_priv_group(self):
        # If the user is in one of the PRIVILEGED_GROUPS, always ALLOW,
        # regardless of whether editGroup is privileged or non-privileged, 
        # or if user is also a member of non-privileged groups
        for user in NON_PRIVILEGED_USERS:
            for group in PRIVILEGED_GROUPS + NON_PRIVILEGED_GROUPS:
                self.runtest(user, PRIVILEGED_GROUPS, group, True)
                self.runtest(user, (PRIVILEGED_GROUPS + NON_PRIVILEGED_GROUPS), group, True)
                self.rundeletetest(user, PRIVILEGED_GROUPS, group, True)
                self.rundeletetest(user, (PRIVILEGED_GROUPS + NON_PRIVILEGED_GROUPS), group, True)

    def test_non_priv_group(self):
        # If the user is in NON_PRIVILEGED_GROUPS, ALLOW if editGroup is also
        # non-privileged
        for user in NON_PRIVILEGED_USERS:
            for group in NON_PRIVILEGED_GROUPS:
                self.runtest(user, NON_PRIVILEGED_GROUPS, group, True)
                self.rundeletetest(user, NON_PRIVILEGED_GROUPS, group, True)

    def test_deny(self):
        # In order to get DENY, user in non-privileged groups must be trying to
        # edit/delete a privileged group
        for user in NON_PRIVILEGED_USERS:
            for group in PRIVILEGED_GROUPS:
                self.runtest(user, NON_PRIVILEGED_GROUPS, group, False)
                self.rundeletetest(user, NON_PRIVILEGED_GROUPS, group, False)

    def test_invalid(self):
        # Validate the exception path
        request = create_request('foo', [], 'bar')
        # This will trigger a KeyError when get_response tries to access the
        # 'userInfo'
        del request.json['request']['userInfo']
        response = group_validation.get_response(request)
        self.assertEqual(
            "Invalid request",
            json.loads(response)['response']['status']['message'])