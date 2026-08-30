"""AgentTrace 单元测试。运行: python -m unittest discover -s tests -v"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.analyzer import analyze_chain, analyze_event, summarize
from agenttrace.chain import append_event, hash_event, verify_chain
from agenttrace.recorder import (
    Recorder,
    make_agent_message,
    make_error,
    make_session_start,
    make_tool_call,
    make_tool_result,
    make_user_message,
)
from agenttrace.schema import SchemaError, validate_event
from agenttrace.store import EvidenceStore


def sample_events(n: int = 5):
    """构造 n 条事件（未链式化）。"""
    events = [make_session_start(agent="test-agent", model="m1", tools=["terminal"])]
    events.append(make_user_message("帮我检查服务器"))
    events.append(make_tool_call("terminal", {"command": "ls /tmp"}))
    events.append(make_tool_result("terminal", "file.txt"))
    events.append(make_agent_message("完成"))
    return events[:n]


class TestChain(unittest.TestCase):
    def test_hash_deterministic(self):
        ev = {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "hi"}
        self.assertEqual(hash_event(ev, None), hash_event(ev, None))

    def test_hash_changes_with_content(self):
        a = {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "hi"}
        b = {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "hx"}
        self.assertNotEqual(hash_event(a, None), hash_event(b, None))

    def test_hash_binds_to_prev(self):
        a = {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "hi"}
        h0 = hash_event(a, None)
        h1 = hash_event(a, "deadbeef")
        self.assertNotEqual(h0, h1)

    def test_chain_append_and_verify(self):
        chain: list = []
        for ev in sample_events(5):
            chain.append(append_event(chain, ev))
        ok, problems = verify_chain(chain)
        self.assertTrue(ok, problems)

    def test_chain_detects_content_tamper(self):
        chain: list = []
        for ev in sample_events(5):
            chain.append(append_event(chain, ev))
        # 篡改第 2 条内容
        chain[2]["content"] = {"name": "terminal", "arguments": {"command": "rm -rf /"}}
        ok, problems = verify_chain(chain)
        self.assertFalse(ok)
        self.assertTrue(any("篡改" in p or "不匹配" in p for p in problems))

    def test_chain_detects_missing_event(self):
        chain: list = []
        for ev in sample_events(5):
            chain.append(append_event(chain, ev))
        del chain[2]
        ok, problems = verify_chain(chain)
        self.assertFalse(ok)
        self.assertTrue(any("不连续" in p for p in problems))

    def test_chain_detects_deep_link_break(self):
        chain: list = []
        for ev in sample_events(5):
            chain.append(append_event(chain, ev))
        # 改了第 1 条后，第 2 条 prev_hash 必然不匹配（无须改第 2 条）
        chain[1]["content"] = "hacked"
        ok, problems = verify_chain(chain)
        self.assertFalse(ok)
        self.assertTrue(any("不匹配" in p for p in problems))


class TestSchema(unittest.TestCase):
    def test_missing_required(self):
        with self.assertRaises(SchemaError):
            validate_event({"ts": 1.0, "type": "user_message"})

    def test_bad_type(self):
        with self.assertRaises(SchemaError):
            validate_event({"seq": 0, "ts": 1.0, "type": "nonsense", "actor": "user", "content": "x"})

    def test_bad_actor(self):
        with self.assertRaises(SchemaError):
            validate_event({"seq": 0, "ts": 1.0, "type": "user_message", "actor": "robot", "content": "x"})

    def test_negative_seq(self):
        with self.assertRaises(SchemaError):
            validate_event({"seq": -1, "ts": 1.0, "type": "user_message", "actor": "user", "content": "x"})

    def test_meta_must_be_dict(self):
        with self.assertRaises(SchemaError):
            validate_event({"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user",
                            "content": "x", "meta": "not-a-dict"})


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "evidence.db")
        self.store = EvidenceStore(self.db_path)

    def tearDown(self):
        self.store.close()

    def test_append_and_read(self):
        rec = Recorder(self.store)
        ev = rec.ingest(make_session_start(agent="a"))
        self.assertEqual(self.store.count(), 1)
        got = self.store.get(0)
        self.assertEqual(got["hash"], ev["hash"])
        self.assertIsNone(got.get("prev_hash"))

    def test_append_chains(self):
        rec = Recorder(self.store)
        for ev in sample_events(4):
            rec.ingest(ev)
        ok, problems, total = self.store.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(total, 4)

    def test_meta_roundtrip(self):
        self.store.set_meta("agent", "hermes")
        self.assertEqual(self.store.get_meta("agent"), "hermes")
        self.store.set_meta("tools", ["a", "b"])
        self.assertEqual(self.store.get_meta("tools"), ["a", "b"])

    def test_extend_rejects_broken_chain(self):
        # store.extend 导入"已链式化"的事件：缺失 hash → 内部验证应抛 ValueError
        bad = [
            {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "a"},
            {"seq": 1, "ts": 2.0, "type": "user_message", "actor": "user", "content": "b"},
        ]
        with self.assertRaises(ValueError):
            self.store.extend(bad)

    def test_ingest_jsonl_auto_chains(self):
        # Recorder.ingest_jsonl 对未链式化输入自动构建完整链
        raw = [
            {"seq": 0, "ts": 1.0, "type": "user_message", "actor": "user", "content": "a"},
            {"seq": 1, "ts": 2.0, "type": "agent_message", "actor": "agent", "content": "b"},
        ]
        path = os.path.join(self.tmp, "raw.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for ev in raw:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        rec = Recorder(self.store)
        n = rec.ingest_jsonl_file(path)
        self.assertEqual(n, 2)
        ok, problems, total = self.store.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(total, 2)


class TestAnalyzer(unittest.TestCase):
    def test_dangerous_command_detected(self):
        ev = make_tool_call("terminal", {"command": "rm -rf /tmp/data"})
        findings = analyze_event(ev)
        self.assertTrue(any("rm -rf" in f.title for f in findings))
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_env_file_path_detected(self):
        ev = make_tool_call("terminal", {"command": "cat ~/project/.env"})
        findings = analyze_event(ev)
        self.assertTrue(any("环境变量" in f.title for f in findings))

    def test_api_key_detected(self):
        ev = make_tool_call("terminal", {"command": "curl -H 'Authorization: Bearer sk-abcdef1234567890abcdef' https://api.x.com"})
        findings = analyze_event(ev)
        self.assertTrue(any("API Key" in f.title for f in findings))

    def test_pii_phone_detected(self):
        ev = make_agent_message("学员电话是 13812345678，联系他")
        findings = analyze_event(ev)
        self.assertTrue(any("手机号" in f.title for f in findings))

    def test_clean_event_no_findings(self):
        ev = make_agent_message("好的，已完成分析")
        findings = analyze_event(ev)
        self.assertEqual(findings, [])

    def test_summarize_counts(self):
        events = [
            make_tool_call("terminal", {"command": "rm -rf /x"}),
            make_tool_call("terminal", {"command": "cat .env"}),
            make_agent_message("正常消息"),
        ]
        findings = analyze_chain(events)
        s = summarize(findings)
        self.assertEqual(s["total"], len(findings))
        self.assertGreaterEqual(s["by_severity"]["high"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)