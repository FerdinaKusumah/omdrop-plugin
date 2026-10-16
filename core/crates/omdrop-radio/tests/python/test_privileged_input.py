"""Caller input never reaches evaluation in the polkit-reachable helper.

Adapted from omdrop-awdl's tests/test_privileged_input.py (0.9.1, 05a2855).
omdrop-discoverable runs as root for any active user, with any argv; bash
arithmetic evaluated array subscripts, so a value like a[$(cmd)] ran cmd. The
original extracted the bash functions and stubbed need_root; this version runs
the omdrop-radio binary unprivileged through its test seam, against the mock
backend, and checks the same outcomes: exit codes, messages, that a payload
never executes, and that nothing past validation starts.
"""
import time
import unittest

from radio_fixture import RadioTestCase


class PrivilegedInputTests(RadioTestCase):
    def supervise(self, *args, token=None):
        env = {} if token is None else {"OMDROP_SUPERVISOR_TOKEN": token}
        return self.radio("__supervise", *args, **env)

    def write_run(self, name, content):
        self.run_dir.mkdir(exist_ok=True)
        (self.run_dir / name).write_text(content)

    def test_a_direct_supervise_call_is_refused(self):
        # What `pkexec omdrop-radio __supervise 0 <payload>` reaches: no token
        # in the environment, because pkexec strips it.
        self.write_run("until", "0")
        result = self.supervise("0", self.payload)
        self.assertEqual(result.returncode, 2)
        self.assertIn("internal", result.stderr)
        self.assert_not_executed(result)
        self.assertEqual(self.spawned(), "")

    def test_a_guessed_token_is_refused_and_leaves_the_real_one(self):
        self.write_run("supervisor.token", "0" * 32)
        result = self.supervise("0", "0", token="1" * 32)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.spawned(), "")
        self.assertEqual((self.run_dir / "supervisor.token").read_text(), "0" * 32)

    def test_a_direct_call_during_a_start_does_not_break_it(self):
        # start has written the token and is spawning its child; another
        # user's `pkexec ... __supervise` lands in between.
        self.write_run("supervisor.token", "cd" * 16)
        self.write_run("until", "1")
        direct = self.supervise("1", "600")
        self.assertEqual(direct.returncode, 2)
        spawned = self.supervise("1", "600", token="cd" * 16)
        self.assertEqual(spawned.returncode, 0, spawned.stderr)
        self.assertIn("started mdns (pid ", self.spawned())
        self.assertFalse((self.run_dir / "supervisor.token").exists())

    def test_numbers_bash_would_misread_are_refused_before_arithmetic(self):
        # 08 and 09 are invalid octal, 010 would be 8, and 20 digits wrap.
        for value in ("08", "09", "010", "9" * 20):
            with self.subTest(value=value):
                start = self.radio("start", value)
                self.assertEqual(start.returncode, 2, start.stderr)
                self.assertIn("usage", start.stderr)
                for args in ((value, "600"), ("0", value)):
                    (self.run_dir / "log").unlink(missing_ok=True)
                    self.write_run("supervisor.token", "ab" * 16)
                    supervised = self.supervise(*args, token="ab" * 16)
                    self.assertEqual(supervised.returncode, 2, supervised.stderr)
                    self.assertIn("must be a number", supervised.stderr)
                    self.assertEqual(self.spawned(), "")

    def test_the_longest_duration_gives_a_deadline_the_child_accepts(self):
        # Cold start: start computes now + secs and passes both to the child,
        # which checks the deadline as a twelve-digit number and secs as a
        # nine-digit one. The longest accepted duration must survive both.
        self.write_run("supervisor.token", "ab" * 16)
        self.write_run("until", "1")
        deadline = str(int(time.time()) + 999999999)
        result = self.supervise(deadline, "999999999", token="ab" * 16)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_one_second_longer_is_refused_before_any_work(self):
        result = self.radio("start", "1000000000")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("at most 999999999", result.stderr)
        self.assertFalse((self.run_dir / "start.lock").exists())
        self.assertEqual(self.calls(), "")

    def test_extending_a_live_window_writes_a_deadline_the_supervisor_accepts(self):
        # A live supervisor, as /proc shows one: our executable, then __supervise.
        supervisor = self.fake_process(self.helper, "__supervise", "0", "0")
        self.record_supervisor(supervisor)
        self.write_run("until", "0")
        extend = self.radio("start", "999999999")
        self.assertEqual(extend.returncode, 5, extend.stderr)
        deadline = (self.run_dir / "until").read_text().strip()
        self.assertRegex(deadline, r"^[1-9][0-9]{0,11}$")
        self.write_run("until", "0")
        refused = self.radio("start", "1000000000")
        self.assertEqual(refused.returncode, 2, refused.stderr)
        self.assertEqual((self.run_dir / "until").read_text(), "0")
        # Extending never reaches the backend.
        self.assertEqual(self.calls(), "")

    def test_read_refuses_iovars_outside_awdl(self):
        for name in ("wsec_key", "pmk", "sae_password", "awdl"):
            with self.subTest(name=name):
                result = self.radio("read", name)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("limited to awdl_", result.stderr)
                self.assertEqual(self.calls(), "")

    def test_read_still_reaches_the_firmware_for_awdl_iovars(self):
        # The original's stubbed GET answered nothing: exit 4, "no reply".
        (self.root / "mock/read.rc").write_text("4")
        for name in ("awdl_peer_table", "ver", "cap"):
            with self.subTest(name=name):
                result = self.radio("read", name, "64")
                self.assertEqual(result.returncode, 4, result.stderr)
                self.assertIn(f"read {name} 64", self.calls())

    def test_read_refuses_a_length_bash_would_misread(self):
        result = self.radio("read", "awdl_stats", "09")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.calls(), "")

    def test_the_spawned_supervisor_still_validates_its_seconds(self):
        # Even with the right token, a non-number never reaches arithmetic,
        # including the BLE wake's seconds.
        self.write_run("supervisor.token", "ab" * 16)
        result = self.supervise("0", self.payload, token="ab" * 16)
        self.assertEqual(result.returncode, 2)
        self.assert_not_executed(result)
        self.assertEqual(self.spawned(), "")

    def test_the_spawned_supervisor_runs_with_a_valid_token(self):
        # The legitimate path: start's token, numeric arguments, and an
        # already-expired deadline so the loop exits at once.
        self.write_run("supervisor.token", "cd" * 16)
        self.write_run("until", "1")
        result = self.supervise("1", "600", token="cd" * 16)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("started mdns (pid ", self.spawned())
        self.assertFalse((self.run_dir / "supervisor.token").exists())

    def test_a_tampered_deadline_file_is_not_evaluated(self):
        self.write_run("supervisor.token", "ef" * 16)
        self.write_run("until", self.payload)
        result = self.supervise("0", "0", token="ef" * 16)
        self.assert_not_executed(result)

    def test_diag_refuses_a_non_numeric_duration(self):
        result = self.radio("diag", self.payload)
        self.assertEqual(result.returncode, 2)
        self.assert_not_executed(result)

    def test_a_tampered_receive_baseline_is_not_evaluated(self):
        # A real supervisor loop, two one-second intervals long, samples a
        # baseline holding a payload: it must replace it, not evaluate it.
        self.fake_awdl0(rx_packets=5)
        self.write_run("rx_base", self.payload)
        self.write_run("announce", "3 1000 1 0 1\n")
        self.write_run("supervisor.token", "ab" * 16)
        self.write_run("until", str(int(time.time()) + 2))
        result = self.supervise("0", "0", token="ab" * 16)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_not_executed(result)
        self.assertEqual((self.run_dir / "rx_base").read_text(), "5")


if __name__ == "__main__":
    unittest.main()
