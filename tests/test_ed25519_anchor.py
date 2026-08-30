"""Ed25519 锚定（anchor_v2）测试：签名验证、攻击检出、无私钥验证。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace import ed25519
from agenttrace import anchor_v2
from agenttrace.chain import append_event
from agenttrace.recorder import (
    Recorder, make_session_start, make_user_message,
    make_tool_call, make_tool_result,
)
from agenttrace.store import EvidenceStore


def build_db(db_path: str, with_meta: bool = True) -> EvidenceStore:
    s = EvidenceStore(db_path)
    r = Recorder(s)
    if with_meta:
        s.set_meta("agent", "hermes")
        s.set_meta("model", "gpt-5.6-luna")
    r.ingest(make_session_start(agent="hermes", model="gpt-5.6-luna", tools=["terminal"]))
    r.ingest(make_user_message("帮我清理旧项目"))
    r.ingest(make_tool_call("terminal", {"command": "ls /data/old"}))
    r.ingest(make_tool_result("terminal", "a b c"))
    r.ingest(make_tool_call("terminal", {"command": "rm -rf /data/old"}))  # 高危
    r.ingest(make_tool_result("terminal", "deleted"))
    return s


class TestEd25519Core(unittest.TestCase):
    def test_rfc8032_vectors(self):
        """RFC 8032 官方向量（T1/T2）。"""
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(ed25519.public_key(sk), pk)
        sig = ed25519.sign(sk, b"")
        self.assertTrue(ed25519.verify(pk, b"", sig))
        self.assertFalse(ed25519.verify(pk, b"x", sig))

    def test_verify_rejects_malformed(self):
        sk = ed25519.generate_secret()
        pk = ed25519.public_key(sk)
        sig = ed25519.sign(sk, b"msg")
        self.assertFalse(ed25519.verify(pk, b"msg", sig[:-1]))
        self.assertFalse(ed25519.verify(pk[:-1], b"msg", sig))
        self.assertFalse(ed25519.verify(pk, b"msg", sig[:-32] + b"\x00" * 32))


class TestEd25519Anchor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "ev.db")
        self.kp = ed25519.Ed25519KeyPair.generate()

    def test_seal_and_verify_pass(self):
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        ok, problems = anchor_v2.verify_ed25519_anchor(self.db, events, meta)
        s.close()
        self.assertTrue(ok, problems)

    def test_verify_without_secret_key(self):
        """核心卖点：验证端完全无私钥也能验证。"""
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        s.close()
        # 模拟验证端：只有锚定文件（内嵌公钥），无私钥
        ok, problems = anchor_v2.verify_ed25519_anchor(self.db, events, meta)
        self.assertTrue(ok, problems)

    def test_attack_full_rebuild_detected(self):
        """整链重算：改内容重算链 → 锚定签名不变 → 检出。"""
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        s.close()
        # 攻击者重算整链
        s = EvidenceStore(self.db)
        evs = s.all_events()
        evs[4]["content"] = {"name": "terminal", "arguments": {"command": "ls /data/old"}}
        nc = []
        for ev in evs:
            e = {k: v for k, v in ev.items() if k not in ("prev_hash", "hash")}
            nc.append(append_event(nc, e))
        for ev in nc:
            s.conn.execute(
                "UPDATE events SET content=?, prev_hash=?, hash=? WHERE seq=?",
                (json.dumps(ev["content"], sort_keys=True, separators=(",", ":")),
                 ev.get("prev_hash"), ev["hash"], ev["seq"]))
        s.conn.commit()
        ok, problems = anchor_v2.verify_ed25519_anchor(self.db, s.all_events(), s.all_meta())
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("链尾哈希" in p or "链尾 seq" in p for p in problems), problems)

    def test_attack_anchor_tamper_detected(self):
        """篡改锚定记录（无私钥重签）→ 签名校验失败。"""
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        s.close()
        path = self.db + ".anchor.json"
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        rec["tip_hash"] = "0" * 64  # 攻击者改锚定但无法重签
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        s = EvidenceStore(self.db)
        ok, problems = anchor_v2.verify_ed25519_anchor(self.db, s.all_events(), s.all_meta())
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("签名校验失败" in p for p in problems), problems)

    def test_attack_wrong_keypair_detected_when_pubkey_bound(self):
        """攻击者用自己的密钥对重签 → 绑定期望公钥的验证端检出（对抗场景核心）。"""
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        s.close()
        # 攻击者整链重算 + 自己的密钥重签
        attacker_kp = ed25519.Ed25519KeyPair.generate()
        s = EvidenceStore(self.db)
        evs = s.all_events()
        evs[4]["content"] = {"name": "terminal", "arguments": {"command": "ls /data/old"}}
        nc = []
        for ev in evs:
            e = {k: v for k, v in ev.items() if k not in ("prev_hash", "hash")}
            nc.append(append_event(nc, e))
        for ev in nc:
            s.conn.execute(
                "UPDATE events SET content=?, prev_hash=?, hash=? WHERE seq=?",
                (json.dumps(ev["content"], sort_keys=True, separators=(",", ":")),
                 ev.get("prev_hash"), ev["hash"], ev["seq"]))
        s.conn.commit()
        s.close()
        # 重签（攻击者能做）
        s = EvidenceStore(self.db)
        anchor_v2.seal_anchor(self.db, s.all_events(), s.all_meta(), attacker_kp)
        s.close()
        # 验证端绑定原始公钥 → 检出伪造
        s = EvidenceStore(self.db)
        ok, problems = anchor_v2.verify_ed25519_anchor(
            self.db, s.all_events(), s.all_meta(),
            expected_public=self.kp.public_hex())
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("公钥" in p for p in problems), problems)

    def test_expected_public_match_passes(self):
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        ok, problems = anchor_v2.verify_ed25519_anchor(
            self.db, events, meta, expected_public=self.kp.public_hex())
        s.close()
        self.assertTrue(ok, problems)

    def test_unbound_verify_cannot_detect_reseal(self):
        """边界（复评 P1）：不绑定期望公钥时，攻击者自签重签无法被检出——
        用测试固定该边界，将来改默认行为时 CI 会提醒此权衡。"""
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        s.close()
        attacker_kp = ed25519.Ed25519KeyPair.generate()
        s = EvidenceStore(self.db)
        evs = s.all_events()
        evs[4]["content"] = {"name": "terminal", "arguments": {"command": "ls /data/old"}}
        nc = []
        for ev in evs:
            e = {k: v for k, v in ev.items() if k not in ("prev_hash", "hash")}
            nc.append(append_event(nc, e))
        for ev in nc:
            s.conn.execute(
                "UPDATE events SET content=?, prev_hash=?, hash=? WHERE seq=?",
                (json.dumps(ev["content"], sort_keys=True, separators=(",", ":")),
                 ev.get("prev_hash"), ev["hash"], ev["seq"]),
            )
        s.conn.commit()
        events_now, meta_now = s.all_events(), s.all_meta()
        s.close()
        anchor_v2.seal_anchor(self.db, events_now, meta_now, attacker_kp)
        s = EvidenceStore(self.db)
        ok, _ = anchor_v2.verify_ed25519_anchor(self.db, s.all_events(), s.all_meta())
        s.close()
        self.assertTrue(ok)  # 不绑定 → 无法检出（这正是 --public-key 必须默认推荐的原因）

    def test_meta_tamper_detected(self):
        s = build_db(self.db)
        events, meta = s.all_events(), s.all_meta()
        anchor_v2.seal_anchor(self.db, events, meta, self.kp)
        # 改 meta
        s.conn.execute("UPDATE meta SET value='\"evil\"' WHERE key='agent'")
        s.conn.commit()
        ok, problems = anchor_v2.verify_ed25519_anchor(
            self.db, s.all_events(), s.all_meta())
        s.close()
        self.assertFalse(ok)
        self.assertTrue(any("meta" in p.lower() for p in problems), problems)


class TestEmptyMetaHint(unittest.TestCase):
    """复评建议：meta 表为空但事件链非空 → verify 提示。"""

    def test_empty_meta_flagged(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "em.db")
        s = build_db(db, with_meta=False)  # 无 meta
        from agenttrace.chain import verify_chain
        events = s.all_events()
        # v2 锚定下 meta 为空也能锚定（hash of {}），但 v1 verify 应提示
        from agenttrace.store import EvidenceStore as ES
        st = ES(db)
        ok, problems, n = st.verify()
        st.close()
        self.assertTrue(any("meta" in p.lower() for p in problems), problems)


if __name__ == "__main__":
    unittest.main(verbosity=2)