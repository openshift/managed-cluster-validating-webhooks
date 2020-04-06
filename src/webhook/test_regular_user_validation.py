import unittest
import json

from webhook.regular_user_validation import is_request_allowed
from webhook.regular_user_validation import get_response

ADMIN_GROUPS = [
    "osd-sre-admins"
]


def create_request(kind, username, groupname):
    class FakeRequest(object):
        def __init__(self):
            self.json = {
                "request": {
                    "uid": "testuser",
                    "operation": "UPDATE",
                    "userInfo": {
                        "username": username
                    },
                    "oldObject": {
                        "metadata": {
                            "name": groupname
                        }
                    },
                    "object": {
                        "kind": kind,
                        "metadata": {
                            "name": groupname
                        }
                    },
                }
            }

        def __getitem__(self, item):
            return getattr(self, item)

    return FakeRequest()


class TestRegularUserValidation(unittest.TestCase):
    def test_is_request_allowed_unauthenticated(self):
        self.assertFalse(is_request_allowed("system:unauthenticated", "", ADMIN_GROUPS))

    def test_is_request_allowed_sre(self):
        self.assertTrue(is_request_allowed("nmalik@redhat.com", ADMIN_GROUPS[0], ADMIN_GROUPS))

    def test_is_request_allowed_kubeadmin(self):
        self.assertTrue(is_request_allowed("kube:admin", "", ADMIN_GROUPS))

    def test_is_request_allowed_systemadmin(self):
        self.assertTrue(is_request_allowed("system:admin", "", ADMIN_GROUPS))

    def test_is_request_allowed_nonadmin_group(self):
        self.assertFalse(is_request_allowed("someuser", "some-group", ADMIN_GROUPS))

    def test_handle_request_allowed_system(self):
        request = create_request("Groups", "kube:admin", ADMIN_GROUPS[0])
        
        response = json.loads(get_response(request, debug=False))
        self.assertTrue(response['response']['allowed'])

    def test_handle_request_allowed_user(self):
        request = create_request("Groups", "some-sre-user", ADMIN_GROUPS[0])
        
        response = json.loads(get_response(request, debug=False))
        self.assertTrue(response['response']['allowed'])

    def test_handle_request_denied(self):
        request = create_request("Groups", "someuser", "")
        
        response = json.loads(get_response(request, debug=False))
        self.assertFalse(response['response']['allowed'])
