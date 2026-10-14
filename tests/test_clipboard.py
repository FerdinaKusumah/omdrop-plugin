"""What `omdrop handle` puts on the clipboard for a received HEIC (#62).

wl-copy is a stand-in that records its arguments and stdin, so the live
clipboard is never touched.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"
HEIF_CONVERT = shutil.which("heif-convert")
MAGICK = shutil.which("magick")
HEIF_ENC = shutil.which("heif-enc")


def stub(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


@unittest.skipUnless(MAGICK and HEIF_ENC and shutil.which("file"), "needs magick, heif-enc and file")
class HeicClipboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "run"
        self.runtime.mkdir(mode=0o700)
        self.calls = self.root / "calls"
        self.calls.mkdir()
        stub(self.bin / "wl-copy",
             'n=$(ls "$CALLS" | wc -l)\n'
             'printf "%s\\n" "$*" > "$CALLS/$n.args"\n'
             'cat > "$CALLS/$n.stdin"\n')
        stub(self.bin / "uwsm-app", '[ "$1" = -- ] && shift\nexec "$@"\n')
        stub(self.bin / "omarchy-notification-send", "exit 0\n")
        self.photo = self.root / "Downloads" / "IMG_0001.HEIC"
        self.photo.parent.mkdir()
        png = self.root / "src.png"
        subprocess.run([MAGICK, "-size", "64x48", "gradient:red-blue", "-depth", "8", str(png)], check=True)
        subprocess.run([HEIF_ENC, "-o", str(self.photo), str(png)], check=True, capture_output=True)
        self.original = self.photo.read_bytes()
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            CALLS=str(self.calls),
            XDG_RUNTIME_DIR=str(self.runtime),
            XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_DATA_HOME=str(self.root / "data"),
        )

    def handle(self):
        result = subprocess.run([OMDROP, "handle", str(self.photo)], env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = sorted(self.calls.glob("*.args"))
        self.assertEqual(len(calls), 1)
        return calls[0].read_text().strip(), calls[0].with_suffix(".stdin")

    def assert_nothing_left(self):
        left = list((self.runtime / "omdrop").glob("clip.*")) if (self.runtime / "omdrop").exists() else []
        self.assertEqual(left, [])
        self.assertEqual(self.photo.read_bytes(), self.original)

    @unittest.skipUnless(HEIF_CONVERT, "needs heif-convert")
    def test_a_heic_goes_on_the_clipboard_as_a_jpeg(self):
        args, stdin = self.handle()
        self.assertEqual(args, "--type image/jpeg")
        kind = subprocess.run(["file", "-b", str(stdin)], capture_output=True, text=True).stdout
        self.assertIn("JPEG image data", kind)
        self.assert_nothing_left()

    def test_a_failing_decoder_falls_back_to_the_path(self):
        stub(self.bin / "heif-convert", 'printf junk > "$4"\nexit 1\n')
        args, stdin = self.handle()
        self.assertEqual(args, "")
        self.assertEqual(stdin.read_text(), str(self.photo))
        self.assert_nothing_left()

    def test_a_missing_decoder_falls_back_to_the_path(self):
        # A PATH holding only the stubs and the basics omdrop needs, none of
        # which is heif-convert.
        for tool in ("bash", "dirname", "basename", "id", "mkdir", "mktemp", "rm",
                     "timeout", "cat", "ls", "wc", "sed", "grep", "tr", "head"):
            real = shutil.which(tool)
            if real and not (self.bin / tool).exists():
                (self.bin / tool).symlink_to(real)
        self.env["PATH"] = str(self.bin)
        args, stdin = self.handle()
        self.assertEqual(args, "")
        self.assertEqual(stdin.read_text(), str(self.photo))
        self.assert_nothing_left()


if __name__ == "__main__":
    unittest.main()
