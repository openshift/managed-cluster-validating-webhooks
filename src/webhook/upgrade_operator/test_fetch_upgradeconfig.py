import unittest
from webhook.upgrade_operator import fetch_upgradeconfig


class TestFetchUpgradeConfig(unittest.TestCase):

    def test_fetch_upgradeconfig_object(self):
        if fetch_upgradeconfig.get_upgradeconfig_cr() is None:
            self.skipTest(
                "Skipping unit test for test_fetch_upgradeconfig.py. To be tested in e2etest.")
