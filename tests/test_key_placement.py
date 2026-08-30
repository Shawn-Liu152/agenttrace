"""4.1/4.2 回归测试：密钥路径策略 + 强攻击信号（复评残留项）。"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace import anchor as anchor_mod
from agenttrace.anchor import (
    AnchorKey, anchor_path_for, anchor_state, ensure_key,
    key_path_for, legacy_key_path_for, resolve_key_path,
)
from agenttrace.recorder import (Recorder, make_session_start, make_user_message)
from agenttrace.store import EvidenceStore


class TestKeyPlacement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "evidence.db")
        self.mock_root = os.path.join(self.tmp, "config", "keys")

    def _patch_root(self):
        patcher = mock.patch.object(anchor_mod, "_key_root", return_value=self.mock_root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_key_default_in_config_dir_not_next_to_db(self):
        """4.1: 默认密钥路径必须在用户配置目录，绝不能与 db 同目录。"""
        self._patch_root()
        kp = key_path_for(self.db)
        self.assertNotEqual(os.path.dirname(kp), os.path.dirname(self.db))
        self.assertEqual(os.path.dirname(kp), self.mock_root)
        # 旧路径（<db>.anchor.key）不应是默认
        self.assertNotEqual(kp, legacy_key_path_for(self.db))

    def test_ensure_key_creates_config_dir(self):
        self._patch_root()
        key = ensure_key(self.db)
        self.assertTrue(os.path.exists(self.mock_root))
        self.assertTrue(os.path.exists(key_path_for(self.db)))
        # 库目录下没有任何密钥文件
        keys_in_db_dir = [f for f in os.listdir(self.tmp) if f.endswith(".key")]
        self.assertEqual(keys_in_db_dir, [])

    def test_resolve_prefers_new_then_legacy(self):
        self._patch_root()
        # 新位置存在 → 用新位置
        key = ensure_key(self.db)
        self.assertEqual(resolve_key_path(self.db), key_path_for(self.db))
        # 删掉新位置、放旧位置 → 回退旧位置（迁移兼容）
        os.remove(key_path_for(self.db))
        legacy = legacy_key_path_for(self.db)
        AnchorKey.generate().save(legacy)
        self.assertEqual(resolve_key_path(self.db), legacy)

    def test_anchor_state_key_location(self):
        self._patch_root()
        self.assertEqual(anchor_state(self.db)["key_location"], "missing")
        ensure_key(self.db)
        st = anchor_state(self.db)
        self.assertTrue(st["key_available"])
        self.assertEqual(st["key_location"], "config-dir")


class TestStrongSignal(unittest.TestCase):
    """4.2: 锚定存在但密钥缺失 = 疑似人为破坏（强攻击信号）。"""

    def test_missing_key_with_anchor_file_is_flagged(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "s.db")
        # 直接构造"锚定文件存在 + 密钥缺失"的现场
        ev0 = {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "a"}
        s = EvidenceStore(db)
        from agenttrace.chain import append_event as ap
        s.extend([ap([], ev0)])
        s.close()
        # 伪造一个锚定文件（无密钥）
        with open(anchor_path_for(db), "w", encoding="utf-8") as f:
            f.write('{"version":1,"mac":"deadbeef"}')
        st = anchor_state(db)
        self.assertTrue(st["has_anchor_file"])
        self.assertFalse(st["key_available"])
        # CLI 层（_print_verify）应返回 2 —— 在 CLI 测试里覆盖
        from agenttrace.cli import _print_verify
        s = EvidenceStore(db)
        rc = _print_verify(s, db)
        s.close()
        self.assertEqual(rc, 2)

    def test_key_in_env_counts_available(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "e.db")
        with mock.patch.dict(os.environ, {"AGENTTRACE_ANCHOR_KEY_HEX": ("ab" * 32)}):
            st = anchor_state(db)
            self.assertTrue(st["key_available"])
            self.assertEqual(st["key_location"], "env")


if __name__ == "__main__":
    unittest.main(verbosity=2)