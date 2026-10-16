"""Receiver readiness uses Debian's comparator and the dynamic loader."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'bin/omdrop').read_text()


def function(name):
    start = SOURCE.index(name + '() {')
    return SOURCE[start:SOURCE.index('\n}', start) + 2]


class UbuntuReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, 'PATH': str(self.root),
                    'PYTHONPATH': str(self.root), 'CALLS': str(self.root / 'calls')}
        (self.root / 'python3').symlink_to(sys.executable)

    def command(self, name, script):
        p = self.root / name
        p.write_text('#!/bin/sh\n' + script)
        p.chmod(0o755)

    def run_function(self, name, preamble=''):
        return subprocess.run(['/bin/bash', '-c', preamble + '\n' + function(name) + '\n' + name],
                              env=self.env, capture_output=True, text=True)

    def contract(self, version, result=0):
        self.env['COMPARISON_RESULT'] = str(result)
        return self.run_function('backend_contract_ok',
                                f'BACKEND_CONTRACT_MIN=0.7.0\nprobe_field() {{ echo "{version}"; }}')

    def test_debian_comparator_used_without_vercmp(self):
        self.command('dpkg', 'echo "$*" > "$CALLS"\nexit "$COMPARISON_RESULT"\n')
        self.assertEqual(self.contract('0.8.1').returncode, 0)
        self.assertEqual((self.root / 'calls').read_text().strip(),
                         '--compare-versions 0.8.1 ge 0.7.0')
        self.assertNotEqual(self.contract('0.6.0', 1).returncode, 0)

    def test_arch_comparator_remains_preferred(self):
        self.command('vercmp', 'echo "$*" > "$CALLS"\necho "$COMPARISON_RESULT"\n')
        self.command('dpkg', 'exit 99\n')
        self.assertEqual(self.contract('0.8.1', 1).returncode, 0)
        self.assertEqual((self.root / 'calls').read_text().strip(), '0.8.1 0.7.0')
        self.assertNotEqual(self.contract('0.6.0', -1).returncode, 0)

    def test_missing_contract_is_rejected(self):
        self.assertNotEqual(self.contract('').returncode, 0)

    def test_library_probe_uses_soname_not_a_distribution_path(self):
        (self.root / 'libarchive.py').write_text('stream_reader = object()\n')
        (self.root / 'sitecustomize.py').write_text('''import ctypes, os
original = ctypes.CDLL
def load(name, *args, **kwargs):
    if name == 'libkeyutils.so.1':
        with open(os.environ['CALLS'], 'w') as f: f.write(name)
        if os.environ.get('MISSING_LIBRARY') == '1': raise OSError('missing')
        return object()
    return original(name, *args, **kwargs)
ctypes.CDLL = load
''')
        self.assertEqual(self.run_function('receiver_libs_installed').returncode, 0)
        self.assertEqual((self.root / 'calls').read_text(), 'libkeyutils.so.1')
        self.env['MISSING_LIBRARY'] = '1'
        self.assertNotEqual(self.run_function('receiver_libs_installed').returncode, 0)


if __name__ == '__main__':
    unittest.main()
