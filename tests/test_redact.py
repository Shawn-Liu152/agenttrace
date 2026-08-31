"""脱敏（--redact v0.6）测试：渲染层打码、证据库本体不动、正常文本不误伤。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.analyzer import analyze_chain, redact_text
from agenttrace.report import _redact_event, generate_report
from agenttrace.recorder import (
    make_session_start, make_tool_call, make_tool_result, make_user_message, Recorder,
)
from agenttrace.store import EvidenceStore

SK = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
GHP = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
BEARER = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PHONE = "13800138000"


class TestRedactText(unittest.TestCase):
    def test_sk_key_masked(self):
        got = redact_text("key: " + SK)
        self.assertNotIn(SK, got)
        self.assertIn("sk-a", got)  # 保留首 4 字符便于定位

    def test_github_token_masked(self):
        got = redact_text(GHP)
        self.assertNotIn(GHP, got)

    def test_aws_key_masked(self):
        tok = "AKIAIOSFODNN7EXAMPLE"
        got = redact_text("aws " + tok)
        self.assertNotIn(tok, got)

    def test_bearer_hex_masked(self):
        got = redact_text("token: " + BEARER)
        self.assertNotIn(BEARER, got)

    def test_password_kv_masked(self):
        tok = "supersecret12345"
        got = redact_text("password=" + tok)
        self.assertNotIn(tok, got)

    def test_phone_masked(self):
        got = redact_text("联系 " + PHONE + " 咨询")
        self.assertNotIn(PHONE, got)

    def test_short_token_not_masked(self):
        tok = "sk-ab"
        got = redact_text("key: " + tok)
        self.assertIn(tok, got)  # 短串不遮（不误伤）

    def test_normal_text_unchanged(self):
        text = "ls /home/user/bin/scripts && python3 train.py"
        self.assertEqual(redact_text(text), text)


class TestRedactReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        db = os.path.join(self.tmp, "e.db")
        s = EvidenceStore(db)
        r = Recorder(s)
        s.set_meta("agent", "hermes")
        s.set_meta("model", "m")
        for ev in (make_session_start(agent="hermes", model="m", tools=["terminal"]),
                   make_user_message("检查配置"),
                   make_tool_call("terminal", {"command": "cat .env"}),
                   make_tool_result("terminal", "API_KEY=" + SK),
                   make_tool_call("terminal", {"command": "curl -H 'Authorization: Bearer " + BEARER + "' https://api.example.com"}),
                   make_tool_result("terminal", "200 OK")):
            r.ingest(ev)
        self.events = s.all_events()
        self.meta = s.all_meta()
        s.close()

    def test_db_content_untouched(self):
        """渲染层打码 ≠ 证据库被改：库里的原始 secret 仍在（证据是链上事实）。"""
        raw = json.dumps(self.events[3]["content"], ensure_ascii=False)
        self.assertIn(SK, raw)

    def test_redact_event_masks_secrets(self):
        masked = _redact_event(self.events[3])
        self.assertNotIn(SK, str(masked["content"]))

    def test_generate_report_redact_flag(self):
        findings = analyze_chain(self.events)
        html_red = generate_report(self.events, findings, self.meta, True, [], "R", redact=True)
        html_no = generate_report(self.events, findings, self.meta, True, [], "R", redact=False)
        self.assertNotIn(SK, html_red)
        self.assertNotIn(BEARER, html_red)
        self.assertIn(SK, html_no)  # 无 redact 时原样保留（用于取证比对）
        self.assertIn("*", html_red)


if __name__ == "__main__":
    unittest.main(verbosity=2)

class TestReportAnchorBadge(unittest.TestCase):
    """Ed25519 seal 后的库，report 应显示"已锚定"徽章（v0.9.1 修复）。"""

    def test_ed25519_anchored_report_shows_badge(self):
        import json as _json
        import tempfile as _tf
        from agenttrace import ed25519 as _ed
        from agenttrace import anchor_v2 as _av2
        from agenttrace.recorder import make_session_start, make_tool_call
        tmp = _tf.mkdtemp()
        db = os.path.join(tmp, "e.db")
        s = EvidenceStore(db)
        r = Recorder(s)
        s.set_meta("agent", "a")
        r.ingest(make_session_start(agent="a"))
        r.ingest(make_tool_call("shell", {"cmd": "ls"}))
        events, meta = s.all_events(), s.all_meta()
        s.close()
        kp = _ed.Ed25519KeyPair.generate()
        _av2.seal_anchor(db, events, meta, kp)
        # 模拟 CLI 判定逻辑（store 无 HMAC key，但 anchor.json 存在）
        from agenttrace.report import generate_report
        from agenttrace.analyzer import analyze_chain
        anchored = os.path.exists(db + ".anchor.json")
        html = generate_report(events, analyze_chain(events), meta, True, [],
                               "T", anchored=anchored, anchor_info="Ed25519")
        self.assertIn("外部锚定有效", html)
