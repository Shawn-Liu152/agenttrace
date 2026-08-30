"""对抗性测试：外部锚定（anchor）对 5 类攻击的检出能力。

评审复现的 3 个 P0 穿透攻击（A 末尾截断 / B 整链重算 / C 元信息篡改）
必须在锚定库上全部转为检出。这是 AgentTrace 从"自洽校验"升级为
"外部锚定取证"的核心回归测试。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.anchor import AnchorKey
from agenttrace.chain import append_event
from agenttrace.recorder import (
    Recorder,
    make_session_start,
    make_tool_call,
    make_tool_result,
    make_user_message,
)
from agenttrace.store import EvidenceStore


def build_anchored_db(db_path: str, key: AnchorKey) -> EvidenceStore:
    """构造带高危命令的锚定证据库（6 条事件）。"""
    s = EvidenceStore(db_path, anchor_key=key)
    r = Recorder(s)
    s.set_meta("agent", "hermes")
    s.set_meta("model", "gpt-5.6-luna")
    r.ingest(make_session_start(agent="hermes", model="gpt-5.6-luna", tools=["terminal"]))
    r.ingest(make_user_message("帮我清理旧项目"))
    r.ingest(make_tool_call("terminal", {"command": "ls /data/old"}))
    r.ingest(make_tool_result("terminal", "a b c"))
    r.ingest(make_tool_call("terminal", {"command": "rm -rf /data/old"}))  # 高危
    r.ingest(make_tool_result("terminal", "deleted"))
    return s


class TestAnchorTamperResistance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.key = AnchorKey.generate()

    def _db(self, name):
        return os.path.join(self.tmp, name)

    def test_normal_anchored_verify_passes(self):
        db = self._db("ok.db")
        s = build_anchored_db(db, self.key)
        ok, problems, n = s.verify()
        s.close()
        self.assertTrue(ok, problems)
        self.assertEqual(n, 6)
        # 锚定文件必须存在
        self.assertTrue(os.path.exists(db + ".anchor.json"))

    def test_attackA_truncation_detected(self):
        """A: 末尾截断（删尾部 rm -rf 及其结果）→ 锚定 seq_max 不匹配。"""
        db = self._db("A.db")
        s = build_anchored_db(db, self.key)
        s.conn.execute("DELETE FROM events WHERE seq >= 4")
        s.conn.commit()
        ok, problems, n = s.verify()
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("链尾 seq" in p for p in problems), problems)

    def test_attackB_full_rebuild_detected(self):
        """B: 整链重算（改 rm -rf 为 ls 后重算全部 hash 回写）→ 锚定 tip 不匹配。"""
        db = self._db("B.db")
        s = build_anchored_db(db, self.key)
        evs = s.all_events()
        evs[4]["content"] = {"name": "terminal", "arguments": {"command": "ls -la /data/old"}}
        newchain = []
        for ev in evs:
            e = {k: v for k, v in ev.items() if k not in ("prev_hash", "hash")}
            newchain.append(append_event(newchain, e))
        for ev in newchain:
            s.conn.execute(
                "UPDATE events SET content=?, prev_hash=?, hash=? WHERE seq=?",
                (json.dumps(ev["content"], sort_keys=True, separators=(",", ":")),
                 ev.get("prev_hash"), ev["hash"], ev["seq"]),
            )
        s.conn.commit()
        ok, problems, n = s.verify()
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("链尾哈希" in p for p in problems), problems)

    def test_attackC_meta_tamper_detected(self):
        """C: 元信息篡改（改 agent 名字）→ 锚定 meta_hash 不匹配。"""
        db = self._db("C.db")
        s = build_anchored_db(db, self.key)  # agent=hermes，锚定含其 hash
        # 攻击者绕过 set_meta 直接改库：meta 值变了但锚定文件没更新
        s.conn.execute("UPDATE meta SET value='\"totally-innocent-agent\"' WHERE key='agent'")
        s.conn.commit()
        ok, problems, n = s.verify()
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("meta" in p.lower() and "不匹配" in p for p in problems), problems)

    def test_attackC_meta_tamper_via_api_detected(self):
        """C': 元信息通过 set_meta 修改也应产生新的有效锚定（API 本身是诚实的采集者）。"""
        db = self._db("C2.db")
        s = build_anchored_db(db, self.key)
        s.set_meta("agent", "renamed-honestly")
        ok, problems, n = s.verify()  # 诚实改名 → 锚定同步更新 → 仍有效
        s.close()
        self.assertTrue(ok, problems)

    def test_attackD_replay_detected(self):
        """D: 重放覆盖（旧事件以新 seq 插入）→ 链不连续。"""
        db = self._db("D.db")
        s = build_anchored_db(db, self.key)
        old = s.get(1)
        s.conn.execute(
            "INSERT INTO events (seq, event_id, ts, type, actor, content, meta, prev_hash, hash) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (old["seq"] + 100, old.get("event_id"), old["ts"], old["type"], old["actor"],
             json.dumps(old["content"], ensure_ascii=False), None, old.get("prev_hash"), old["hash"]),
        )
        s.conn.commit()
        ok, problems, n = s.verify()
        s.close()
        self.assertFalse(ok)

    def test_attackE_timestamp_forge_detected(self):
        """E: 时间戳伪造 → 内容哈希不匹配。"""
        db = self._db("E.db")
        s = build_anchored_db(db, self.key)
        s.conn.execute("UPDATE events SET ts=? WHERE seq=5", (820000000.0,))
        s.conn.commit()
        ok, problems, n = s.verify()
        s.close()
        self.assertFalse(ok)

    def test_anchor_file_itself_tampered(self):
        """F: 直接改锚定文件（改了 tip 但无密钥重签）→ MAC 校验失败。"""
        db = self._db("F.db")
        s = build_anchored_db(db, self.key)
        s.close()
        apath = db + ".anchor.json"
        rec = json.load(open(apath, encoding="utf-8"))
        rec["tip_hash"] = "0" * 64
        json.dump(rec, open(apath, "w", encoding="utf-8"))
        s = EvidenceStore(db, anchor_key=self.key)
        ok, problems, n = s.verify()
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("签名校验失败" in p for p in problems), problems)

    def test_wrong_key_fails(self):
        """G: 用错误密钥验证 → MAC 校验失败（密钥即信任根）。"""
        db = self._db("G.db")
        s = build_anchored_db(db, self.key)
        s.close()
        wrong = AnchorKey.generate()
        s = EvidenceStore(db, anchor_key=wrong)
        ok, problems, n = s.verify()
        s.close()
        self.assertFalse(ok)

    def test_unanchored_verify_flags_warning(self):
        """H: 未锚定库 verify 必须显式警告（不能假装安全）。"""
        db = self._db("H.db")
        s = EvidenceStore(db)
        r = Recorder(s)
        r.ingest(make_session_start(agent="a"))
        r.ingest(make_user_message("hi"))
        ok, problems, n = s.verify()
        s.close()
        # 链自洽 → ok=True，但必须带"未锚定"警告（CLI 层会返回 warning 级别）
        self.assertTrue(ok)
        self.assertTrue(any("未锚定" in p for p in problems), problems)


class TestStoreNoOverwrite(unittest.TestCase):
    def test_duplicate_seq_rejected(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "ow.db")
        s = EvidenceStore(db)
        r = Recorder(s)
        r.ingest(make_session_start(agent="a"))  # seq 0
        # 直接往 store 写一个 seq=0 的事件（绕过 recorder 的自动编号）
        dup = {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "dup"}
        with self.assertRaises(ValueError):
            s.append(dup)
        self.assertEqual(s.count(), 1)
        s.close()

    def test_extend_duplicate_rejected(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "ow2.db")
        s = EvidenceStore(db)
        # 先导入一条合法链
        ev0 = {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "a"}
        from agenttrace.chain import append_event as ap
        chain = [ap([], ev0)]
        s.extend(chain)
        # 再尝试导入 seq 0 冲突的链 → 拒绝
        chain2 = [ap([], {"seq": 0, "ts": 2.0, "type": "user_message", "actor": "user", "content": "b"})]
        with self.assertRaises(ValueError):
            s.extend(chain2, start_seq=0)
        s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)