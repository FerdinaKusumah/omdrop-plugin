"""libkeyutils is found the way the receiver loads it, not at an Arch path.

receiver_libs_installed checked for /usr/lib/libkeyutils.so.1, which on
Debian and Ubuntu lives under /lib/<triplet>, so the receiver's libraries
always read as missing there. The two tests answer the loader question with a
python3 wrapper: one fails without the fix where the file is absent (Debian,
Ubuntu), the other where it is present (Arch).
"""
import shutil
import unittest

import test_radio_backend as radio
from test_radio_backend import helper

REAL_PYTHON = shutil.which("python3")


def receiver_libarchive_available():
    try:
        from libarchive import stream_reader  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(receiver_libarchive_available(), "needs libarchive-c")
class KeyutilsProbeTests(unittest.TestCase):
    setUp = radio.RadioBackendTests.setUp
    command = radio.RadioBackendTests.command
    omdrop = radio.RadioBackendTests.omdrop
    doctor = radio.RadioBackendTests.doctor

    def loader_finds_keyutils(self, found):
        # Any python3 call that loads libkeyutils succeeds or fails as told;
        # every other call runs the real interpreter.
        self.command("python3",
                     "#!/bin/sh\n"
                     f'case "$*" in *libkeyutils*) exit {0 if found else 1} ;; esac\n'
                     f'exec {REAL_PYTHON} "$@"\n')
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True,
            "contract": "0.7.0", "missing": []}))
        return {m["id"] for m in self.doctor()["missing"]}

    def test_a_loadable_libkeyutils_counts_as_installed(self):
        self.assertNotIn("library", self.loader_finds_keyutils(True))

    def test_an_unloadable_libkeyutils_is_reported(self):
        self.assertIn("library", self.loader_finds_keyutils(False))


if __name__ == "__main__":
    unittest.main()
