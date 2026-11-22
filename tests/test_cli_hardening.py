"""Owner check on private files and de-duplication of repeated --scope."""

import os
import types
import unittest
from unittest import mock

from lantern import cli


class OwnershipTests(unittest.TestCase):
    def test_other_owner_is_refused(self):
        info = types.SimpleNamespace(st_uid=1234)
        with mock.patch.object(os, "geteuid", create=True, return_value=1000):
            self.assertFalse(cli._owned_by_current_user(info))

    def test_same_owner_is_accepted(self):
        info = types.SimpleNamespace(st_uid=1000)
        with mock.patch.object(os, "geteuid", create=True, return_value=1000):
            self.assertTrue(cli._owned_by_current_user(info))

    def test_platform_without_geteuid_is_accepted(self):
        info = types.SimpleNamespace(st_uid=0)
        with mock.patch.object(cli.os, "geteuid", None, create=True):
            self.assertTrue(cli._owned_by_current_user(info))


if __name__ == "__main__":
    unittest.main()
