"""The account is read from the certificate subject in either OpenSSL format.

OpenSSL 3.0 (Debian 12, Ubuntu 22.04 and 24.04) prints `CN = value`; newer
releases print `CN=value`. Only the latter was matched, so on OpenSSL 3.0
every Apple-issued certificate came back unbound and Contacts Only refused
every sender. A stand-in openssl prints each format, so the test does not
depend on the installed version.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))
import contacts  # noqa: E402

FAKE_OPENSSL = """#!/bin/sh
case "$1" in
  verify) exit 0 ;;
  x509)
    for arg in "$@"; do
      [ "$prev" = -out ] && { cat > "$arg"; exit 0; }
      prev=$arg
    done
    printf '%s\\n' "$FAKE_SUBJECT" ;;
esac
"""

ACCOUNT = "000123-05-abcdef"


class SubjectCnTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        bin_dir = Path(tmp.name)
        openssl = bin_dir / "openssl"
        openssl.write_text(FAKE_OPENSSL)
        openssl.chmod(0o755)
        self.ca = bin_dir / "root.pem"
        self.ca.write_text("root")
        self.path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"

    def account_for(self, subject):
        with mock.patch.dict(os.environ, PATH=self.path, FAKE_SUBJECT=subject):
            return contacts.certificate_account(b"der", ca_file=str(self.ca), untrusted=[])

    def test_openssl_3_0_spaced_subject(self):
        subject = f"subject=O = Apple Inc., CN = {contacts.CN_PREFIX}{ACCOUNT}"
        self.assertEqual(self.account_for(subject), ACCOUNT)

    def test_compact_subject(self):
        subject = f"subject=O=Apple Inc., CN={contacts.CN_PREFIX}{ACCOUNT}"
        self.assertEqual(self.account_for(subject), ACCOUNT)

    def test_a_self_signed_airdrop_certificate_has_no_account(self):
        self.assertEqual(self.account_for("subject=CN = airdrop"), "")


if __name__ == "__main__":
    unittest.main()
