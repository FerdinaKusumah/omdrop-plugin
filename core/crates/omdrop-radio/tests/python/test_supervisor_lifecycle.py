"""Supervisor recognition and cleanup.

Adapted from omdrop-awdl's tests/test_supervisor_lifecycle.py. The original
ran the bash supervisor_pid/supervisor_alive/supervisor_pids functions with a
grep that always fails (Omarchy's grep replacement cannot search
/proc/*/cmdline). Here the same situations are driven through omdrop-radio's
`status` and `stop`: the binary reads /proc itself and runs no grep, which
the failing grep first on PATH keeps honest.
"""
import json
import os
import unittest

from radio_fixture import RadioTestCase


class SupervisorLifecycleTests(RadioTestCase):
    def setUp(self):
        super().setUp()
        grep = self.root / "bin" / "grep"
        grep.write_text("#!/bin/sh\nexit 1\n")
        grep.chmod(0o755)
        self.run_dir.mkdir()

    def env(self, **extra):
        env = super().env(**extra)
        env["PATH"] = f"{self.root / 'bin'}:{env['PATH']}"
        return env

    def test_recorded_supervisor_is_recognized_without_grep(self):
        self.fake_awdl0()
        supervisor = self.fake_process(self.helper, "__supervise", "0", "0")
        self.record_supervisor(supervisor)
        (self.run_dir / "until").write_text("0")

        result = self.radio("status", "--json")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["visible"], result.stdout)

    def test_a_recorded_pid_with_another_start_time_is_not_alive(self):
        # The pid was reused: argv and owner match, the start time does not.
        self.fake_awdl0()
        supervisor = self.fake_process(self.helper, "__supervise", "0", "0")
        start = self.start_time(supervisor.pid)
        (self.run_dir / "supervisor").write_text(f"{supervisor.pid} {start + 1}\n")
        (self.run_dir / "until").write_text("0")
        (self.run_dir / "reason").write_text("ok")

        status = json.loads(self.radio("status", "--json").stdout)

        self.assertFalse(status["visible"])
        self.assertEqual(status["reason"], "expired")

    def test_a_recorded_pid_that_is_not_our_supervisor_is_not_alive(self):
        self.fake_awdl0()
        stranger = self.fake_process(self.root / "lib" / "other", "__supervise", "0", "0")
        self.record_supervisor(stranger)
        (self.run_dir / "until").write_text("0")
        (self.run_dir / "reason").write_text("ok")

        status = json.loads(self.radio("status", "--json").stdout)

        self.assertFalse(status["visible"])
        self.assertEqual(status["reason"], "expired")

    def test_all_owned_supervisors_are_enumerated_for_cleanup(self):
        first = self.fake_process(self.helper, "__supervise", "0", "0")
        second = self.fake_process(self.helper, "__supervise", "0", "0")
        # Another program's supervisor: same verb, different executable.
        unrelated = self.fake_process(self.root / "lib" / "omdrop-discoverable", "__supervise", "0", "0")
        # Ours as later arguments of another program: not a supervisor.
        posing = self.fake_process(self.root / "lib" / "other", "x", self.helper, "__supervise")

        result = self.radio("stop")

        self.assertEqual(result.returncode, 0, result.stderr)
        for owned in (first, second):
            owned.wait(timeout=5)
        self.assertIsNone(unrelated.poll())
        self.assertTrue(os.path.exists(f"/proc/{unrelated.pid}"))
        self.assertIsNone(posing.poll())

    def test_the_supervisor_pair_counts_only_at_the_start_of_argv(self):
        self.fake_awdl0()
        posing = self.fake_process(self.root / "lib" / "other", "x", self.helper, "__supervise")
        self.record_supervisor(posing)
        (self.run_dir / "until").write_text("0")

        status = json.loads(self.radio("status", "--json").stdout)

        self.assertFalse(status["visible"])


if __name__ == "__main__":
    unittest.main()
