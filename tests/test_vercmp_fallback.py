"""The backend contract is compared without pacman's vercmp.

vercmp ships with pacman, so outside Arch `$(vercmp ...)` expanded to nothing
and a current omdrop-owl was reported as following a contract older than the
one it meets. These tests hide vercmp from PATH on any machine, so they fail
without the fallback even where pacman is installed.
"""
import json
import os
import unittest
from pathlib import Path

import test_radio_backend as radio
from test_radio_backend import helper


class ContractWithoutVercmpTests(unittest.TestCase):
    setUp = radio.RadioBackendTests.setUp
    command = radio.RadioBackendTests.command
    omdrop = radio.RadioBackendTests.omdrop
    doctor = radio.RadioBackendTests.doctor

    def without_vercmp(self):
        # Every command on PATH except vercmp, so the script runs as it would
        # on Debian or Ubuntu.
        shim = Path(self.tmp.name) / "path-without-vercmp"
        shim.mkdir()
        for d in os.environ["PATH"].split(os.pathsep):
            if not os.path.isdir(d):
                continue
            for name in os.listdir(d):
                target = Path(d) / name
                if name != "vercmp" and not (shim / name).exists() and os.access(target, os.X_OK):
                    (shim / name).symlink_to(target)
        self.env["PATH"] = f"{self.bin}{os.pathsep}{shim}"

    def backend_findings(self, contract):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True,
            "contract": contract, "missing": []}))
        self.without_vercmp()
        return [m for m in self.doctor()["missing"] if m["id"] == "backend"]

    def test_the_minimum_contract_is_accepted(self):
        self.assertEqual(self.backend_findings("0.7.0"), [])

    def test_a_newer_contract_is_compared_by_number_not_by_text(self):
        self.assertEqual(self.backend_findings("0.10.0"), [])

    def test_an_older_contract_is_still_refused(self):
        findings = self.backend_findings("0.6.9")
        self.assertEqual(len(findings), 1, json.dumps(findings))
        self.assertIn("older than the 0.7.0", findings[0]["say"])


if __name__ == "__main__":
    unittest.main()
