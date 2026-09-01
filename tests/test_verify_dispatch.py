"""复评 v1.0 P1 跨命令端到端测试：verify 锚定体系分派。

覆盖三条路径：
  A. init → record → seal seal (Ed25519) → verify
     —— 必须报"Ed25519 外部锚定"而非"疑似人为破坏"（修复点）
  B. init --anchor (HMAC) → record → seal seal (覆盖为 Ed25519) → verify
     —— 同样不得报"缺 mac"或"人为破坏"
  C. init --anchor (HMAC) → record → 删除密钥 → verify
     —— 确认是 HMAC 体系，必须保留"疑似人为破坏"强信号
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(args, cwd):
    env = {**os.environ, "PYTHONPATH": ROOT}
    return subprocess.run([sys.executable, "-m", "agenttrace"] + args,
                          capture_output=True, text=True, cwd=cwd, env=env,
                          timeout=180)


class TestVerifyDispatchEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sample = os.path.join(ROOT, "examples", "sample_session.jsonl")

    def test_a_ed25519_seal_verify_ok_no_false_alarm(self):
        """路径 A：纯 Ed25519 流程 verify 不得报"疑似人为破坏"。"""
        db = os.path.join(self.tmp, "e.db")
        for cli in (["seal", "keygen", "--db", db],
                    ["init", "--db", db, "--agent", "h", "--model", "m"],
                    ["record", self.sample, "--db", db],
                    ["seal", "seal", "--db", db]):
            r = run_cli(cli, self.tmp)
            self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-500:])
        r = run_cli(["verify", "--db", db], self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Ed25519 外部锚定", r.stdout)
        self.assertNotIn("疑似人为破坏", r.stdout)
        self.assertNotIn("签名密钥缺失", r.stdout)

    def test_b_hmac_then_seal_overwrite_no_error(self):
        """路径 B：先 HMAC 后 seal 覆盖，verify 不得报"缺 mac"。"""
        db = os.path.join(self.tmp, "e2.db")
        for cli in (["init", "--db", db, "--agent", "h", "--anchor"],
                    ["record", self.sample, "--db", db],
                    ["seal", "seal", "--db", db]):
            r = run_cli(cli, self.tmp)
            self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-500:])
        r = run_cli(["verify", "--db", db], self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Ed25519 外部锚定", r.stdout)
        self.assertNotIn("疑似人为破坏", r.stdout)
        self.assertNotIn("缺少 mac", r.stdout)

    def test_c_hmac_key_deleted_still_strong_signal(self):
        """路径 C：确认 HMAC 体系 + 密钥缺失 → 仍报强信号（不能为了不误报而漏报）。"""
        # 终评 4.2：测试必须封闭——用 AGENTTRACE_ANCHOR_KEY_PATH 把密钥隔离到
        # 临时目录，绝不读写真实用户配置目录。
        key_dir = tempfile.mkdtemp()
        key_file = os.path.join(key_dir, "test.key")
        env = {**os.environ, "PYTHONPATH": ROOT,
               "AGENTTRACE_ANCHOR_KEY_PATH": key_file}
        db = os.path.join(self.tmp, "e3.db")

        def run_env(args):
            return subprocess.run([sys.executable, "-m", "agenttrace"] + args,
                                  capture_output=True, text=True, cwd=self.tmp,
                                  env=env, timeout=180)

        for cli in (["init", "--db", db, "--agent", "h", "--anchor"],
                    ["record", self.sample, "--db", db]):
            r = run_env(cli)
            self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-500:])
        self.assertTrue(os.path.exists(key_file), "密钥应写入 AGENTTRACE_ANCHOR_KEY_PATH")
        os.remove(key_file)  # 模拟销毁验证能力（只删临时目录的密钥，不碰用户环境）
        r = run_env(["verify", "--db", db])
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("疑似人为破坏", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)