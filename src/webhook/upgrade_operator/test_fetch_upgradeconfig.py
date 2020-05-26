import unittest
from webhook.upgrade_operator import fetch_upgradeconfig


class TestFetchUpgradeConfig(unittest.TestCase):

    def validate_upgraceconfig_object(self, request_json):
        doc_keys = request_json.keys()

        if 'kind' not in doc_keys:
            return False

        if request_json['items'][0]['kind'] == "UpgradeConfig":
            return True
        return False

    def test_fetch_upgradeconfig_object(self):
        if fetch_upgradeconfig.get_upgradeconfig_cr() is None:
            self.skipTest(
                "Skipping unit test for test_fetch_upgradeconfig.py. To be tested in e2etest.")
        else:
            self.assertTrue((self.validate_upgraceconfig_object(
                fetch_upgradeconfig.get_upgradeconfig_cr())), "Valid UpgradeConfig resource")
