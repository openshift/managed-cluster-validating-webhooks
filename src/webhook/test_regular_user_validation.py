import unittest
import json

from webhook.regular_user_validation import is_request_allowed
from webhook.regular_user_validation import get_response

ADMIN_GROUPS = [
    "osd-sre-admins"
]


def create_request(username, groups):
    class FakeRequest(object):
        def __init__(self):
            self.json = {
                "request": {
                    "uid": "testuser",
                    "operation": "UPDATE",
                    "userInfo": {
                        "username": username,
                        "groups": groups,
                    },
                    "object": {
                        "kind": "TestResources",
                    }
                }
            }

        def __getitem__(self, item):
            return getattr(self, item)

    return FakeRequest()


class RegularUserValidationBase(object):
    """Mixin providing test logic.

    To use:
    - Create a class inheriting from both this and unittest.TestCase.
    - Set the `username` and `expect` variables.
      . `username` is the username in the request
      . `expect` is a boolean indicating whether we expect the request to be
        allowed (True) or denied (False).
    - Override methods that behave unusually.
    """
    def runtests(self, testGroups, expect_override=None):
        exp = expect_override if expect_override is not None else self.expect
        self.assertEqual(
            exp,
            is_request_allowed(self.username, testGroups, ADMIN_GROUPS))

        request = create_request(self.username, testGroups)

        response = json.loads(get_response(request, debug=False))
        self.assertEqual(exp, response['response']['allowed'])

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


class TestRegularUserValidation_Unauthenticated(unittest.TestCase,
                                                RegularUserValidationBase):
    username = "system:unauthenticated"
    expect = False


class TestRegularUserValidation_kubeadmin(unittest.TestCase,
                                          RegularUserValidationBase):
    username = "kube:admin"
    expect = True


class TestRegularUserValidation_systemadmin(unittest.TestCase,
                                            RegularUserValidationBase):
    username = "system:admin"
    expect = True


class TestRegularUserValidation_sreUser(unittest.TestCase,
                                        RegularUserValidationBase):
    username = "nmalik@redhat.com"
    expect = True

    def runtests(self, testGroups, expect_override=None):
        # for these tests, add the SRE group to every request
        testGroups.append(ADMIN_GROUPS[0])
        super(TestRegularUserValidation_sreUser, self).runtests(
            testGroups, expect_override=expect_override)


class TestRegularUserValidation_nonSreGroup(unittest.TestCase,
                                            RegularUserValidationBase):
    username = "someOtherUser"
    expect = False

    def test_sreGroup(self):
        # This one ALLOWs because we're passing the SRE group
        self.runtests([ADMIN_GROUPS[0]], expect_override=True)

    def test_manyGroups_sreGroup(self):
        # This one ALLOWs because we're passing the SRE group
        self.runtests(["something-else", ADMIN_GROUPS[0]],
                      expect_override=True)
