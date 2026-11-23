"""Commands run during a scan never open a console window on Windows (the tray has none)."""

import os
import subprocess
import unittest
from unittest import mock

from lantern import discovery


class NoConsoleWindowTests(unittest.TestCase):
    def calls(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"Reply from 127.0.0.1: ttl=128\n")
        with mock.patch.object(discovery.subprocess, "run", return_value=result) as run:
            discovery.ping_host("127.0.0.1")
            discovery._run_text(["arp", "-a"])
        return [call.kwargs for call in run.call_args_list]

    @unittest.skipUnless(os.name == "nt", "console windows are a Windows concern")
    def test_ping_and_system_commands_are_hidden_on_windows(self):
        for kwargs in self.calls():
            self.assertTrue(kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW)
            self.assertEqual(kwargs["startupinfo"].wShowWindow, 0)

    def test_other_systems_get_no_extra_arguments(self):
        with mock.patch.object(discovery.os, "name", "posix"):
            self.assertEqual(discovery._no_window(), {})
