"""The config is read with tomli where tomllib is missing (Python < 3.11).

Ubuntu 22.04 ships Python 3.10: the receiver, `omdrop name` and every other
config read died on `import tomllib`. A sitecustomize hides tomllib and offers
the same parser as tomli, so these tests fail without the fallback on any
Python version.
"""
import ast
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "omdrop"
SERVE = ROOT / "bin" / "airdrop-serve.py"

SITECUSTOMIZE = textwrap.dedent("""\
    import importlib.abc
    import sys
    try:
        import tomllib as _parser
    except ModuleNotFoundError:
        import tomli as _parser
    sys.modules["tomli"] = _parser
    sys.modules.pop("tomllib", None)

    class _NoTomllib(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path, target=None):
            if name == "tomllib":
                raise ModuleNotFoundError("No module named 'tomllib'", name=name)
            return None

    sys.meta_path.insert(0, _NoTomllib())
""")

# Runs airdrop-serve.py's load_config alone: importing the script starts the
# receiver, so only load_config and the two key lists it checks against run.
LOAD_CONFIG = textwrap.dedent("""\
    import ast, sys
    tree = ast.parse(open(sys.argv[1]).read())
    wanted = {"CONFIG_KEYS", "STRING_CONFIG_KEYS"}
    keep = [n for n in tree.body
            if (isinstance(n, ast.Assign)
                and {getattr(t, "id", None) for t in n.targets} & wanted)
            or (isinstance(n, ast.FunctionDef) and n.name == "load_config")]
    ns = {}
    exec(compile(ast.Module(body=keep, type_ignores=[]), sys.argv[1], "exec"), ns)
    print(ns["load_config"](sys.argv[2]))
""")


def toml_parser_dir():
    """Where tomllib or tomli lives, so the parser is found under a temp HOME."""
    try:
        import tomllib as parser
    except ModuleNotFoundError:
        try:
            import tomli as parser
        except ModuleNotFoundError:
            return None
    return str(Path(parser.__file__).resolve().parent.parent)


@unittest.skipUnless(toml_parser_dir(), "needs tomllib or tomli")
class TomllibFallbackTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        site = self.home / "site"
        site.mkdir()
        (site / "sitecustomize.py").write_text(SITECUSTOMIZE)
        # Nothing is receiving, so `omdrop name` never restarts the real unit.
        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        systemctl = bin_dir / "systemctl"
        systemctl.write_text('#!/bin/sh\ncase "$*" in *is-active*) echo inactive; exit 3 ;; esac\nexit 0\n')
        systemctl.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update(PATH=f"{bin_dir}{os.pathsep}{self.env['PATH']}",
                        HOME=str(self.home),
                        XDG_CONFIG_HOME=str(self.home / ".config"),
                        PYTHONPATH=os.pathsep.join([str(site), toml_parser_dir()]))

    def test_the_hidden_tomllib_really_is_hidden(self):
        result = subprocess.run([sys.executable, "-c", "import tomllib"],
                                env=self.env, capture_output=True, text=True)
        self.assertIn("No module named 'tomllib'", result.stderr)

    def test_the_cli_writes_and_reads_the_name(self):
        wrote = subprocess.run([CLI, "name", "Study Mac"], env=self.env, capture_output=True, text=True)
        self.assertEqual(wrote.returncode, 0, wrote.stderr)
        read = subprocess.run([CLI, "name"], env=self.env, capture_output=True, text=True)
        self.assertEqual(read.stdout.strip(), "Study Mac", read.stderr)

    def test_the_receiver_reads_the_config(self):
        config = self.home / "config.toml"
        config.write_text('name = "Study Mac"\n')
        result = subprocess.run([sys.executable, "-c", LOAD_CONFIG, str(SERVE), str(config)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(ast.literal_eval(result.stdout.strip())["name"], "Study Mac")


if __name__ == "__main__":
    unittest.main()
