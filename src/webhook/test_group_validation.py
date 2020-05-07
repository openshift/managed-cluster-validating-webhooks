import unittest
import json
import os

from webhook import group_validation


def create_request(user, memberGroups, editGroup, operation="update"):
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
                "operation": operation,
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

    PRIVILEGED_USERS = (
        "kube:admin",
        "system:admin",
    )

    PRIVILEGED_GROUPS_1 = (
        # need 2 privileged groups groupings - priv groups 1 can edit/delete
        # priv groups 2, but priv groups 2 cannot edit priv groups 1
        # These are tuples so they're immutable, forcing the test case to
        # duplicate in order to change them. Otherwise we have potential
        # collisions among test cases.
        ("osd-sre-admins"),
        ("osd-sre-cluster-admins"),
    )

    PRIVILEGED_GROUPS_2 = (
        # need 2 privileged groups groupings - priv groups 1 can edit/delete
        # priv groups 2, but priv groups 2 cannot edit priv groups 1
        # These are tuples so they're immutable, forcing the test case to
        # duplicate in order to change them. Otherwise we have potential
        # collisions among test cases.
        ("dedicated-admins"),
        ("cluster-admins"),
        ("layered-cs-sre-admins"),
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
        ("random_group"),
    )

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

    def group_validation_response(self, *args, **kwargs):
        resp_json = group_validation.get_response(*args, **kwargs)
        return json.loads(resp_json)['response']

    def test_exclusive_group(self):
        """Test GROUP_VALIDATION_EXCLUSIVE_GROUP_PREFIXES config.

        When enforced, this will allow users from group A to exclusively
        apply Operations on group A by specifying group A's prefix.
        
        """
        req = create_request(
            "alice", 
            ["layered-cs-sre-admins", "osd-sre-cluster-admins"], 
            "layered-cs-sre-admins")
        res = self.group_validation_response(
            req,
            exclusive_group_prefixes=["layered-"]
        )
        # Allow user as it is part of the admin and exclusive groups
        self.assertEqual(True, res["allowed"]) 
        req = create_request(
            "alice", 
            ["layered-cs-sre-admins",], 
            "layered-cs-sre-admins")
        res = self.group_validation_response(
            req,
            exclusive_group_prefixes=["layered-"]
        )
        # Disallow user as it is not an admin
        self.assertEqual(False, res["allowed"]) 
        req = create_request(
            "alice", 
            ["osd-sre-cluster-admins"], 
            "layered-cs-sre-admins")
        res = self.group_validation_response(
            req,
            exclusive_group_prefixes=["layered-"]
        )
        # Disallow user as it is not part of 
        # the exclusive group even if it's admin
        self.assertEqual(False, res["allowed"]) 
        req = create_request(
            "alice", 
            ["group-we-dont-care"], 
            "layered-cs-sre-admins")
        res = self.group_validation_response(
            req,
            exclusive_group_prefixes=["layered-"]
        )
        # Disallow user as it is not part of 
        # the exclusive group that is protected
        self.assertEqual(False, res["allowed"]) 
        self.assertEqual(False, res["allowed"]) 
        req = create_request(
            "alice", 
            ["group-we-dont-care"], 
            "group-we-dont-care")
        res = self.group_validation_response(
            req,
            exclusive_group_prefixes=["non-pro"]
        )
        # Allow user as we don't care about the group and not protected  
        self.assertEqual(True, res["allowed"]) 

    def test_priv_user(self):
        # If the username is kube:admin or system:admin, always ALLOW,
        # regardless of whether memberGroups or editGroup is privileged
        # or non-privileged
        for user in self.PRIVILEGED_USERS:
            for group in self.PRIVILEGED_GROUPS_1 + self.PRIVILEGED_GROUPS_2 + self.NON_PRIVILEGED_GROUPS:
                self.runtest(user, self.PRIVILEGED_GROUPS_1, group, True)
                self.runtest(user, self.PRIVILEGED_GROUPS_2, group, True)
                self.runtest(user, self.NON_PRIVILEGED_GROUPS, group, True)
                self.rundeletetest(user, self.PRIVILEGED_GROUPS_1, group, True)
                self.rundeletetest(user, self.PRIVILEGED_GROUPS_2, group, True)
                self.rundeletetest(user, self.NON_PRIVILEGED_GROUPS, group, True)

    def test_priv_group(self):
        # If the user is in one of the PRIVILEGED_GROUPS_1, always ALLOW,
        # regardless of whether editGroup is privileged or non-privileged,
        # or if user is also a member of non-privileged groups
        for user in self.NON_PRIVILEGED_USERS:
            for group in self.PRIVILEGED_GROUPS_1 + self.PRIVILEGED_GROUPS_2 + self.NON_PRIVILEGED_GROUPS:
                self.runtest(user, self.PRIVILEGED_GROUPS_1, group, True)
                self.runtest(user, (self.PRIVILEGED_GROUPS_1 + self.NON_PRIVILEGED_GROUPS), group, True)
                self.runtest(user, (self.PRIVILEGED_GROUPS_1 + self.PRIVILEGED_GROUPS_2), group, True)
                self.runtest(user, (self.PRIVILEGED_GROUPS_1 + self.PRIVILEGED_GROUPS_2 + self.NON_PRIVILEGED_GROUPS), group, True)
                self.rundeletetest(user, self.PRIVILEGED_GROUPS_1, group, True)
                self.rundeletetest(user, (self.PRIVILEGED_GROUPS_1 + self.NON_PRIVILEGED_GROUPS), group, True)
                self.rundeletetest(user, (self.PRIVILEGED_GROUPS_1 + self.PRIVILEGED_GROUPS_2), group, True)
                self.rundeletetest(user, (self.PRIVILEGED_GROUPS_1 + self.PRIVILEGED_GROUPS_2 + self.NON_PRIVILEGED_GROUPS), group, True)

    def test_non_priv_group(self):
        # If the user is in PRIVILEGED_GROUP_2 and/or NON_PRIVILEGED_GROUPS, 
        # ALLOW if editGroup is also non-privileged
        for user in self.NON_PRIVILEGED_USERS:
            for group in self.NON_PRIVILEGED_GROUPS:
                self.runtest(user, self.NON_PRIVILEGED_GROUPS, group, True)
                self.runtest(user, self.PRIVILEGED_GROUPS_2, group, True)
                self.runtest(user, self.PRIVILEGED_GROUPS_2 + self.NON_PRIVILEGED_GROUPS, group, True)
                self.rundeletetest(user, self.NON_PRIVILEGED_GROUPS, group, True)
                self.rundeletetest(user, self.PRIVILEGED_GROUPS_2, group, True)
                self.rundeletetest(user, self.PRIVILEGED_GROUPS_2 + self.NON_PRIVILEGED_GROUPS, group, True)

    def test_deny(self):
        # In order to get DENY, user in PRIVILEGED_GROUPS_2 and/or 
        # NON_PRIVILEGED_GROUPS must be trying to edit/delete a group in
        # PRIVILEGED_GROUPS_1 or PRIVILEGED_GROUPS_2
        for user in self.NON_PRIVILEGED_USERS:
            for group in self.PRIVILEGED_GROUPS_1 + self.PRIVILEGED_GROUPS_2:
                self.runtest(user, self.NON_PRIVILEGED_GROUPS, group, False)
                self.runtest(user, self.PRIVILEGED_GROUPS_2, group, False)
                self.runtest(user, self.NON_PRIVILEGED_GROUPS + self.PRIVILEGED_GROUPS_2, group, False)
                self.rundeletetest(user, self.NON_PRIVILEGED_GROUPS, group, False)
                self.rundeletetest(user, self.PRIVILEGED_GROUPS_2, group, False)
                self.rundeletetest(user, self.NON_PRIVILEGED_GROUPS + self.PRIVILEGED_GROUPS_2, group, False)

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
