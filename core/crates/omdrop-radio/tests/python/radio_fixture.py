"""A private omdrop-radio install for the adapted omdrop-awdl suites.

The suites in this directory are omdrop-awdl's tests/test_privileged_input.py
and tests/test_supervisor_lifecycle.py, adapted: those extracted bash functions
from omdrop-discoverable and ran them with need_root stubbed out; these run the
omdrop-radio binary as a black box, unprivileged, through its test seam
(OMDROP_RADIO_TEST_ROOT, honoured only when neither uid is 0) against the mock
backend in ../mock-backend.

The binary: $OMDROP_RADIO_BIN, else $CARGO_TARGET_DIR/debug/omdrop-radio, else
the workspace's target/debug/omdrop-radio. Build it first:
    cargo build -p omdrop-radio
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MOCK = HERE.parent / "mock-backend"
WORKSPACE = HERE.parents[3]
HOOKS = ("probe", "up", "identity", "tick", "down", "peer-watch", "peers", "diag", "read", "trace")


def binary():
    candidates = [os.environ.get("OMDROP_RADIO_BIN")]
    if os.environ.get("CARGO_TARGET_DIR"):
        candidates.append(os.path.join(os.environ["CARGO_TARGET_DIR"], "debug", "omdrop-radio"))
    candidates.append(str(WORKSPACE / "target" / "debug" / "omdrop-radio"))
    for c in candidates:
        if c and os.access(c, os.X_OK):
            return Path(c)
    raise unittest.SkipTest("omdrop-radio is not built; run cargo build -p omdrop-radio or set OMDROP_RADIO_BIN")


class RadioTestCase(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0 or os.getuid() == 0:
            self.skipTest("the test seam is ignored as root, by design")
        # State files the tests plant must pass the helper's trust check
        # (owned by us, not writable by group or others).
        os.umask(0o022)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_dir = self.root / "run"
        for d in ("lib", "hooks", "mock", "conf", "proc/sys/kernel", "bin"):
            (self.root / d).mkdir(parents=True)
        for d in ("lib", "hooks"):
            (self.root / d).chmod(0o755)
        # A copy per test: supervisors are matched by their exact executable.
        self.helper = self.root / "lib" / "omdrop-radio"
        self.install(binary(), self.helper)
        self.install(MOCK / "omdrop-adv", self.root / "lib" / "omdrop-adv")
        for hook in HOOKS:
            self.install(MOCK / "hook", self.root / "hooks" / hook)
        (self.root / "proc/sys/kernel/hostname").write_text("testhost\n")
        self.marker = self.root / "executed"
        self.payload = f"a[$(touch {self.marker})]"
        self.processes = []
        self.addCleanup(self.cleanup)

    @staticmethod
    def install(src, dst):
        shutil.copy(src, dst)
        os.chmod(dst, 0o755)

    def cleanup(self):
        subprocess.run([self.helper, "stop"], env=self.env(), capture_output=True)
        for p in self.processes:
            p.kill()
            p.wait()
        root = os.fsencode(str(self.root))
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                if root in Path(f"/proc/{pid}/cmdline").read_bytes():
                    os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass

    def env(self, **extra):
        env = {"PATH": os.environ.get("PATH", "/usr/bin"), "OMDROP_RADIO_TEST_ROOT": str(self.root)}
        env.update(extra)
        return env

    def radio(self, *args, **env):
        return subprocess.run([self.helper, *args], env=self.env(**env), capture_output=True, text=True)

    def fake_awdl0(self, rx_packets=0):
        net = self.root / "sys/class/net/awdl0"
        (net / "statistics").mkdir(parents=True, exist_ok=True)
        (net / "statistics/rx_packets").write_text(f"{rx_packets}\n")
        (self.root / "proc/net").mkdir(parents=True, exist_ok=True)
        (self.root / "proc/net/if_inet6").write_text(
            "fe800000000000000000000000000001 0b 40 20 80 awdl0\n")

    def fake_process(self, *argv):
        """A process whose /proc/<pid>/cmdline is exactly argv, argv[0] included:
        cat run under that argv[0], blocked opening argv[1], a FIFO in its
        working directory that nobody writes."""
        argv = [str(a) for a in argv]
        cwd = Path(tempfile.mkdtemp(dir=self.root))
        os.mkfifo(cwd / argv[1])
        p = subprocess.Popen(argv, executable=shutil.which("cat"), cwd=cwd,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(p)
        deadline = time.time() + 5
        want = b"\0".join(os.fsencode(a) for a in argv) + b"\0"
        while Path(f"/proc/{p.pid}/cmdline").read_bytes() != want:
            if time.time() > deadline:
                self.fail("fake process never showed its argv")
            time.sleep(0.01)
        return p

    @staticmethod
    def start_time(pid):
        """Field 22 of /proc/<pid>/stat: what `supervisor` records beside the pid."""
        stat = Path(f"/proc/{pid}/stat").read_text()
        return int(stat[stat.rindex(")") + 2:].split()[19])

    def record_supervisor(self, process):
        self.run_dir.mkdir(exist_ok=True)
        (self.run_dir / "supervisor").write_text(f"{process.pid} {self.start_time(process.pid)}\n")

    def spawned(self):
        """Children the supervisor started: its `started <tag>` log lines.
        (The advertiser's own record can lose the race with an immediate
        expiry, which kills it before it writes anything.)"""
        log = self.run_dir / "log"
        lines = log.read_text().splitlines() if log.exists() else []
        return "".join(line.split(" ", 1)[1] + "\n" for line in lines if " started " in line)

    def calls(self):
        path = self.root / "calls"
        return path.read_text() if path.exists() else ""

    def assert_not_executed(self, result):
        self.assertFalse(self.marker.exists(), f"payload ran: {result.stderr}")
