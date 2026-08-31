"""批量模式（batch，v1.0 性能优化）测试：语义等价 + 锚定正确 + commit 时序。"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.anchor import AnchorKey
from agenttrace.recorder import make_tool_call, make_tool_result, make_user_message
from agenttrace.store import EvidenceStore


class TestBatchMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_batch_appends_same_as_individual(self):
        """批量与逐条 append 产生相同哈希链（语义等价）。"""
        db1 = os.path.join(self.tmp, "a.db")
        db2 = os.path.join(self.tmp, "b.db")
        evs = [make_user_message("m%d" % i) for i in range(50)]

        s1 = EvidenceStore(db1)
        for ev in evs:
            s1.append(ev)
        h1 = [e["hash"] for e in s1.all_events()]

        s2 = EvidenceStore(db2)
        with s2.batch():
            for ev in evs:
                s2.append(ev)
        h2 = [e["hash"] for e in s2.all_events()]
        self.assertEqual(h1, h2)
        ok, problems, _ = s2.verify()
        self.assertTrue(ok, problems)
        s1.close()
        s2.close()

    def test_batch_with_anchor_updates_once_and_valid(self):
        """批量 + 锚定：块结束后锚定一次且有效（O(n) 替代 O(n²)）。"""
        db = os.path.join(self.tmp, "a.db")
        s = EvidenceStore(db, anchor_key=AnchorKey.generate())
        evs = [make_tool_call("shell", {"cmd": "cmd%d" % i}) for i in range(20)]
        with s.batch():
            for ev in evs:
                s.append(ev)
            # 块内锚定尚未更新（延迟）——不查，避免断言依赖实现细节
        ok, problems, n = s.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(n, 20)
        # 锚定文件存在且 tip 与库里一致
        import json
        rec = json.load(open(db + ".anchor.json", encoding="utf-8"))
        tail = s.all_events()[-1]
        self.assertEqual(rec["tip_hash"], tail["hash"])
        s.close()

    def test_nested_batch_commits_once(self):
        db = os.path.join(self.tmp, "n.db")
        s = EvidenceStore(db)
        with s.batch():
            s.append(make_user_message("x"))
            with s.batch():
                s.append(make_user_message("y"))
            s.append(make_user_message("z"))
        # 嵌套退出全部后链完整
        ok, problems, n = s.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(n, 3)
        s.close()

    def test_batch_tail_cache_consistent(self):
        """批量内链尾缓存：seq 必须连续、prev_hash 正确。"""
        db = os.path.join(self.tmp, "t.db")
        s = EvidenceStore(db)
        with s.batch():
            for i in range(10):
                s.append(make_user_message("m%d" % i))
        evs = s.all_events()
        for i in range(1, len(evs)):
            self.assertEqual(evs[i]["prev_hash"], evs[i - 1]["hash"])
            self.assertEqual(evs[i]["seq"], evs[i - 1]["seq"] + 1)
        s.close()

    def test_batch_exception_rolls_back(self):
        """复评 v1.0 P2：块内异常 → 整体回滚（取证"全有或全无"）。"""
        db = os.path.join(self.tmp, "e.db")
        s = EvidenceStore(db)
        with self.assertRaises(RuntimeError):
            with s.batch():
                s.append(make_user_message("ok"))
                raise RuntimeError("boom")
        s.append(make_user_message("after"))
        evs = s.all_events()
        self.assertEqual(len(evs), 1)  # 事务回滚，'ok' 未落库
        self.assertEqual(evs[0]["content"], "after")
        ok, problems, _ = s.verify()
        self.assertTrue(ok, problems)
        s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)