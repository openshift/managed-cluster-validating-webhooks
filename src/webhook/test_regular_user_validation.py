import unittest

from webhook.regular_user_validation import is_request_allowed

ADMIN_GROUPS = [
    "osd-sre-admins"
]

class TestRegularUserValidation(unittest.TestCase):
    def test_unauthenticated(self):
        self.assertFalse(is_request_allowed("system:unauthenticated", "", ADMIN_GROUPS))

    def test_sre(self):
        self.assertTrue(is_request_allowed("nmalik@redhat.com", ADMIN_GROUPS[0], ADMIN_GROUPS))

    def test_kubeadmin(self):
        self.assertTrue(is_request_allowed("kube:admin", "", ADMIN_GROUPS))

    def test_systemadmin(self):
        self.assertTrue(is_request_allowed("system:admin", "", ADMIN_GROUPS))

    def test_nonadmin_group(self):
        self.assertFalse(is_request_allowed("someuser", "some-group", ADMIN_GROUPS))
