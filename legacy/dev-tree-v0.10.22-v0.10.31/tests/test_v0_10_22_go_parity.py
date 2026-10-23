"""The Go launcher and the Python backend must compute identical handshake proofs (v0.10.22).

Extracts launchProof / identityProof / pipEnvironment / broadPrincipal from
release/native_launcher.go (which is Windows-only) into a throwaway program and runs it with the
local Go toolchain. Skipped when Go is not installed.
"""

from __future__ import annotations

import hmac
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import conftest_env  # noqa: F401

from app.core import security

LAUNCHER = Path(__file__).resolve().parents[1] / "release" / "native_launcher.go"


def _func(src: str, name: str) -> str:
    i = src.index(f"func {name}(")
    depth = 0
    for k in range(src.index("{", i), len(src)):
        depth += {"{": 1, "}": -1}.get(src[k], 0)
        if depth == 0:
            return src[i : k + 1]
    raise ValueError(name)


MAIN = """
func main() {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	fmt.Println(launchProof(strings.Repeat("f0", 32), 8766, strings.Repeat("ab", 32)))
	fmt.Println(identityProof(key, 8765, strings.Repeat("ab", 32)))
	os.Setenv("PIP_INDEX_URL", "https://mirror.example/simple")
	os.Setenv("PYTHONPATH", "evil")
	python, mirror := 0, 0
	for _, kv := range pipEnvironment() {
		u := strings.ToUpper(kv)
		if strings.HasPrefix(u, "PYTHONPATH=") {
			python++
		}
		if strings.HasPrefix(u, "PIP_INDEX_URL=") {
			mirror++
		}
	}
	fmt.Println(python, mirror)
	fmt.Println(broadPrincipal("S-1-5-11"), broadPrincipal("S-1-5-21-1-2-3-1001"))
}
"""


@unittest.skipUnless(shutil.which("go"), "Go toolchain not installed")
class GoParity(unittest.TestCase):
    def test_proofs_and_pip_environment(self):
        src = LAUNCHER.read_text(encoding="utf-8")
        body = "\n\n".join(_func(src, n) for n in ("launchProof", "identityProof", "pipEnvironment", "broadPrincipal"))
        prog = (
            'package main\n\nimport (\n\t"crypto/hmac"\n\t"crypto/sha256"\n\t"encoding/hex"\n\t"fmt"\n\t"os"\n\t"strings"\n)\n\n'
            + body
            + MAIN
        )
        with tempfile.TemporaryDirectory() as d:
            Path(d, "main.go").write_text(prog, encoding="utf-8")
            out = subprocess.run(["go", "run", "main.go"], cwd=d, capture_output=True, text=True, timeout=300)
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = out.stdout.split()
        self.assertEqual(lines[0], security.launch_proof("f0" * 32, "ab" * 32, 8766))
        key = bytes(range(32))
        self.assertEqual(lines[1], hmac.new(key, ("nodewatch-identity:v2:8765:" + "ab" * 32).encode(), "sha256").hexdigest())
        self.assertEqual(lines[2], "0", "PYTHON* variables (code injection into pip) must not reach pip")
        self.assertEqual(lines[3], "1", "PIP_* settings (corporate mirrors) are honoured; hashes make them safe")
        self.assertEqual(lines[4:6], ["true", "false"])


if __name__ == "__main__":
    unittest.main()
