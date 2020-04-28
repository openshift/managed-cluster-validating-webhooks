import unittest
import json

from webhook.regular_user_validation import is_request_allowed
from webhook.regular_user_validation import get_response

ADMIN_GROUPS = ["osd-sre-admins"]


def create_request(username, groups):
    class FakeRequest(object):
        def __init__(self):
            self.json = {
                "request": {
                    "uid": "testuser",
                    "operation": "UPDATE",
                    "userInfo": {"username": username, "groups": groups,},
                    "object": {"kind": "TestResources",},
                }
            }

        def __getitem__(self, item):
            return getattr(self, item)

    return FakeRequest()


class TestRegularUserValidation_Unauthenticated(unittest.TestCase):
    username = "system:unauthenticated"

    def runtests(self, testGroups):
        self.assertFalse(is_request_allowed(self.username, testGroups, ADMIN_GROUPS))

        request = create_request(self.username, testGroups)

        response = json.loads(get_response(request, debug=False))
        self.assertFalse(response["response"]["allowed"])

    def test_noGroup(self):
        self.runtests([])

    def test_sreGroup(self):
        self.runtests([ADMIN_GROUPS[0]])

    def test_nonSreGroup(self):
        self.runtests(["something-else"])

    def test_manyGroups(self):
        self.runtests(["something-else", "other-thing"])

    def test_manyGroups_sreGroup(self):
        self.runtests(["something-else", ADMIN_GROUPS[0]])


class TestRegularUserValidation_kubeadmin(unittest.TestCase):
    username = "kube:admin"

    def runtests(self, testGroups):
        self.assertTrue(is_request_allowed(self.username, testGroups, ADMIN_GROUPS))

        request = create_request(self.username, testGroups)

        response = json.loads(get_response(request, debug=False))
        self.assertTrue(response["response"]["allowed"])

    def test_noGroup(self):
        self.runtests([])

    def test_sreGroup(self):
        self.runtests([ADMIN_GROUPS[0]])

    def test_nonSreGroup(self):
        self.runtests(["something-else"])

    def test_manyGroups(self):
        self.runtests(["something-else", "other-thing"])

    def test_manyGroups_sreGroup(self):
        self.runtests(["something-else", ADMIN_GROUPS[0]])


class TestRegularUserValidation_systemadmin(unittest.TestCase):
    username = "system:admin"

    def runtests(self, testGroups):
        self.assertTrue(is_request_allowed(self.username, testGroups, ADMIN_GROUPS))

        request = create_request(self.username, testGroups)

        response = json.loads(get_response(request, debug=False))
        self.assertTrue(response["response"]["allowed"])

    def test_noGroup(self):
        self.runtests([])

    def test_sreGroup(self):
        self.runtests([ADMIN_GROUPS[0]])

    def test_nonSreGroup(self):
        self.runtests(["something-else"])

    def test_manyGroups(self):
        self.runtests(["something-else", "other-thing"])

    def test_manyGroups_sreGroup(self):
        self.runtests(["something-else", ADMIN_GROUPS[0]])


class TestRegularUserValidation_sreUser(unittest.TestCase):
    username = "nmalik@redhat.com"
    sreGroup = ADMIN_GROUPS[0]

    def runtests(self, testGroups):
        # for these tests, add the SRE group to every request
        testGroups.append(self.sreGroup)
        self.assertTrue(is_request_allowed(self.username, testGroups, ADMIN_GROUPS))

        request = create_request(self.username, testGroups)
        response = json.loads(get_response(request, debug=False))
        self.assertTrue(response["response"]["allowed"])

    def test_noGroup(self):
        self.runtests([])

    def test_sreGroup(self):
        self.runtests([ADMIN_GROUPS[0]])

    def test_nonSreGroup(self):
        self.runtests(["something-else"])

    def test_manyGroups(self):
        self.runtests(["something-else", "other-thing"])

    def test_manyGroups_sreGroup(self):
        self.runtests(["something-else", ADMIN_GROUPS[0]])


class TestRegularUserValidation_nonSreGroup(unittest.TestCase):
    username = "someOtherUser"

    def runtests(self, testGroups):
        self.assertFalse(is_request_allowed(self.username, testGroups, ADMIN_GROUPS))

        request = create_request(self.username, testGroups)
        response = json.loads(get_response(request, debug=False))
        self.assertFalse(response["response"]["allowed"])

    def test_noGroup(self):
        self.runtests([])

    def test_nonSreGroup(self):
        self.runtests(["something-else"])

    def test_manyGroups(self):
        self.runtests(["something-else", "other-thing"])
