"""Windows cp1252 控制台编码回归测试（v1.1.1 跨平台修复）。

背景：CLI 输出含 Unicode 符号（✔/✘/⚠/🔐），Windows CI 控制台默认
cp1252 编码，print 直接 UnicodeEncodeError 崩溃（本地 UTF-8 环境不
复现——所以必须在测试里强制窄编码）。
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli_cp1252(args, cwd):
    """在强制 cp1252 编码的子进程中跑 CLI（复现 Windows CI 场景）。"""
    env = {**os.environ, "PYTHONPATH": ROOT,
           "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    return subprocess.run([sys.executable, "-m", "agenttrace"] + args,
                          capture_output=True, text=True, cwd=cwd, env=env,
                          timeout=180)


class TestCp1252Console(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "ev.db")

    def test_init_via_cp1252(self):
        """init 输出含 ✔/🔑，cp1252 下不得炸。"""
        r = run_cli_cp1252(["init", "--db", self.db, "--agent", "t",
                            "--anchor"], self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("初始化", r.stdout)

    def test_verify_via_cp1252(self):
        """verify 输出含 ✔/🔐/⚠ 分支，cp1252 下不得炸（含强信号路径）。"""
        r1 = run_cli_cp1252(["init", "--db", self.db, "--agent", "t",
                             "--anchor"], self.tmp)
        self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
        r2 = run_cli_cp1252(["verify", "--db", self.db], self.tmp)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertIn("外部锚定", r2.stdout)

    def test_analyze_report_via_cp1252(self):
        """report 生成（大数据量输出路径）cp1252 下不得炸。"""
        sample = os.path.join(ROOT, "examples", "sample_session.jsonl")
        for c in (["init", "--db", self.db, "--agent", "t", "--anchor"],
                  ["record", sample, "--db", self.db],
                  ["report", "--db", self.db,
                   "--out", os.path.join(self.tmp, "r.html")]):
            r = run_cli_cp1252(c, self.tmp)
            self.assertEqual(r.returncode, 0, c[0] + ": " + r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)