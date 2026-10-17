"""The receiver's libraries are checked with the interpreter the unit runs.

receiver_libs_installed ran a bare `python3`, so a PATH that shadows it (mise,
pyenv, asdf, a venv) without libarchive-c reported the libraries as missing
while the receiver, which runs /usr/bin/python3, imported them fine (#52).
"""
import shutil
import unittest

import test_radio_backend as radio
from test_radio_backend import helper

REAL_PYTHON = shutil.which("python3")
PROBE = "*stream_reader*"


class ReceiverPythonTests(unittest.TestCase):
    setUp = radio.RadioBackendTests.setUp
    command = radio.RadioBackendTests.command
    omdrop = radio.RadioBackendTests.omdrop
    doctor = radio.RadioBackendTests.doctor

    def interpreter(self, name, has_libs):
        self.command(name,
                     "#!/bin/sh\n"
                     f'case "$*" in {PROBE}) exit {0 if has_libs else 1} ;; esac\n'
                     f'exec {REAL_PYTHON} "$@"\n')
        return str(self.bin / name)

    def library_finding(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True,
            "contract": "0.7.0", "missing": []}))
        return "library" in {m["id"] for m in self.doctor()["missing"]}

    def test_a_shadowing_python3_without_the_libraries_is_ignored(self):
        self.interpreter("python3", has_libs=False)
        self.env["OMDROP_RECEIVER_PYTHON"] = self.interpreter("receiver-python", has_libs=True)
        self.assertFalse(self.library_finding())

    def test_the_receivers_interpreter_without_the_libraries_is_reported(self):
        self.interpreter("python3", has_libs=True)
        self.env["OMDROP_RECEIVER_PYTHON"] = self.interpreter("receiver-python", has_libs=False)
        self.assertTrue(self.library_finding())


if __name__ == "__main__":
    unittest.main()
