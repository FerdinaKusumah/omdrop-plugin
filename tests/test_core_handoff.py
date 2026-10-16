"""`bin/omdrop` hands every command to an installed omdrop-core.

The panel, the PATH link and the systemd units all run this script, so this
one hand-off is what moves a user to core. It must pass the arguments through
untouched and keep `$0`, which core uses to find this plugin; it must stay out
of the way when `OMDROP_IMPLEMENTATION=python` asks for the bash, and when
core is not installed; `rust` must not fall back silently; an unknown value
is refused; and it must never hand off to itself.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"


class CoreHandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.core = Path(self.tmp.name) / "omdrop-core"
        # A stand-in for /usr/bin/omdrop: report how it was called.
        self.core.write_text('#!/bin/bash\nprintf "core argv0=%s args=" "$0"\n'
                             'printf "[%s]" "$@"\necho\nexit 7\n')
        self.core.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if k != "OMDROP_IMPLEMENTATION"}
        self.env["OMDROP_CORE"] = str(self.core)

    def run_omdrop(self, *args, **env):
        return subprocess.run([str(OMDROP), *args], env={**self.env, **env},
                              capture_output=True, text=True, timeout=30)

    def test_installed_core_gets_the_command_and_its_args_untouched(self):
        run = self.run_omdrop("send", "--to", "a b", "x")
        self.assertEqual(run.returncode, 7, run.stderr)
        self.assertTrue(run.stdout.strip().endswith("args=[send][--to][a b][x]"), run.stdout)

    def test_installed_core_sees_this_script_as_argv0(self):
        # Core finds the plugin through the path it was run as. A shebang
        # script cannot see argv[0] (the kernel puts the interpreter there),
        # so a real executable stands in: Python keeps it in sys.orig_argv.
        python = Path(sys.executable).resolve()
        run = self.run_omdrop("-c", "import sys; print(sys.orig_argv[0])",
                              OMDROP_CORE=str(python))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), str(OMDROP))

    def test_python_keeps_the_bash(self):
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="python")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(run.stdout.startswith("omdrop "), run.stdout)
        self.assertNotIn("core argv0", run.stdout)

    def test_rust_uses_core(self):
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="rust")
        self.assertEqual(run.returncode, 7, run.stderr)
        self.assertIn("core argv0", run.stdout)

    def test_rust_without_core_is_an_error_not_a_fallback(self):
        absent = str(Path(self.tmp.name) / "absent")
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="rust", OMDROP_CORE=absent)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertIn("omdrop-core is not installed", run.stderr)

    def test_an_unknown_value_is_refused(self):
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="pyhton")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertEqual(run.stderr,
                         'omdrop: OMDROP_IMPLEMENTATION must be python or rust, not "pyhton"\n')

    def test_no_core_installed_runs_the_bash(self):
        run = self.run_omdrop("version", OMDROP_CORE=str(Path(self.tmp.name) / "absent"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(run.stdout.startswith("omdrop "), run.stdout)

    def test_a_core_path_that_is_this_script_does_not_loop(self):
        link = Path(self.tmp.name) / "omdrop"
        link.symlink_to(OMDROP)
        run = self.run_omdrop("version", OMDROP_CORE=str(link))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(run.stdout.startswith("omdrop "), run.stdout)


if __name__ == "__main__":
    unittest.main()
