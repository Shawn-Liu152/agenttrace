"""Agent 框架适配器（adapters v0.8）测试：消息→事件转换、工具调用、链完整。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.adapters import (
    ingest_langgraph_state, ingest_messages, ingest_openai_response_events,
)
from agenttrace.store import EvidenceStore


def new_store(tmp, name="e.db"):
    return EvidenceStore(os.path.join(tmp, name))


class TestIngestMessages(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = new_store(self.tmp)

    def _messages(self):
        return [
            {"role": "user", "content": "帮我部署一下"},
            {"role": "assistant", "content": "好的，先看当前目录",
             "tool_calls": [{"id": "call_1",
                             "function": {"name": "shell", "arguments": "{\"cmd\": \"ls\"}"}}]},
            {"role": "tool", "tool_call_id": "call_1", "name": "shell",
             "content": "a.py b.py"},
            {"role": "assistant", "content": "部署完成"},
        ]

    def test_chat_completions_conversion(self):
        n = ingest_messages(self.store, self._messages(), agent="hermes", model="gpt-5")
        evs = self.store.all_events()
        self.assertEqual(n, len(evs))
        types = [e["type"] for e in evs]
        self.assertIn("session_start", types)
        self.assertIn("user_message", types)
        self.assertEqual(types.count("tool_call"), 1)  # shell call
        self.assertEqual(types.count("tool_result"), 1)
        self.assertEqual(types.count("agent_message"), 2)
        # chain 完整
        ok, problems, total = self.store.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(total, len(evs))
        # meta 记录
        meta = self.store.all_meta()
        self.assertEqual(meta.get("agent"), "hermes")
        self.assertEqual(meta.get("model"), "gpt-5")

    def test_langgraph_conversion(self):
        msgs = [
            {"type": "human", "content": "查一下天气"},
            {"type": "ai", "content": "我来查",
             "tool_calls": [{"name": "weather", "args": {"city": "北京"}, "id": "t1"}]},
            {"type": "tool", "name": "weather", "content": "晴，25°C"},
            {"type": "ai", "content": "北京今天晴天"},
        ]
        n = ingest_langgraph_state(self.store, msgs, agent="lg-agent", model="claude-4")
        evs = self.store.all_events()
        types = [e["type"] for e in evs]
        self.assertEqual(types.count("tool_call"), 1)
        tc = next(e for e in evs if e["type"] == "tool_call")
        self.assertEqual(tc["content"]["name"], "weather")
        self.assertEqual(tc["content"]["arguments"]["city"], "北京")
        ok, problems, _ = self.store.verify()
        self.assertTrue(ok, problems)

    def test_tool_args_string_and_object(self):
        # LangGraph: args 可能是对象；OpenAI: arguments 是 JSON 字符串
        msgs = [
            {"type": "ai", "content": "ok",
             "tool_calls": [{"name": "a", "args": {"x": 1}},
                            {"name": "b", "args": '{"y": 2}'}]},
        ]
        ingest_langgraph_state(self.store, msgs, agent="a")
        evs = self.store.all_events()
        calls = [e for e in evs if e["type"] == "tool_call"]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["content"]["arguments"], {"x": 1})
        self.assertEqual(calls[1]["content"]["arguments"], {"y": 2})

    def test_no_session_duplicate(self):
        # 第二次 ingest 同库：不再重复 session_start
        self._messages()
        ingest_messages(self.store, [{"role": "user", "content": "hi"}],
                        agent="hermes", model="m")
        first = ingest_messages(self.store, [{"role": "user", "content": "再次"}],
                                agent="hermes", model="m")
        evs = self.store.all_events()
        self.assertEqual(sum(1 for e in evs if e["type"] == "session_start"), 1)
        self.assertEqual(first, 1)  # 只新加 1 条


class TestOpenAIResponsesStream(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = new_store(self.tmp)

    def _stream_events(self):
        """模拟 Responses API 流：文本增量 + 工具调用 + 输出。"""
        return [
            {"type": "response.created", "response": {"model": "gpt-5"}},
            {"type": "response.output_text.delta", "delta": "我来", "ts": 1.0},
            {"type": "response.output_text.delta", "delta": "处理", "ts": 1.1},
            {"type": "response.output_item.added",
             "item": {"type": "function_call", "id": "fc_1", "name": "shell",
                      "arguments": ""}, "output_index": 0, "ts": 1.2},
            {"type": "response.function_call_arguments.delta", "delta": "{\"cmd\":", "ts": 1.3},
            {"type": "response.function_call_arguments.delta", "delta": " \"ls\"}", "ts": 1.4},
            {"type": "response.output_item.done",
             "item": {"type": "function_call_output", "output": "ok", "id": "fc_1"},
             "ts": 1.5},
            {"type": "response.completed", "ts": 1.6},
        ]

    def test_responses_stream_merging(self):
        n = ingest_openai_response_events(self.store, self._stream_events(),
                                          agent="hermes", model="gpt-5")
        evs = self.store.all_events()
        self.assertEqual(n, len(evs))
        types = [e["type"] for e in evs]
        self.assertIn("session_start", types)
        # 文本 delta 合并成 1 条
        txts = [e for e in evs if e["type"] == "agent_message"]
        self.assertEqual(len(txts), 1)
        self.assertEqual(txts[0]["content"], "我来处理")
        # 工具调用参数合并
        calls = [e for e in evs if e["type"] == "tool_call"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["content"]["arguments"], {"cmd": "ls"})
        self.assertEqual(calls[0]["content"].get("tool_call_id"), "fc_1")
        # 工具结果
        self.assertEqual(sum(1 for e in evs if e["type"] == "tool_result"), 1)
        ok, problems, _ = self.store.verify()
        self.assertTrue(ok, problems)

    def test_responses_unknown_events_skipped(self):
        events = self._stream_events() + [{"type": "response.some_unknown", "x": 1},
                                          {"type": "error", "code": "x"}]
        n = ingest_openai_response_events(self.store, events, agent="a")
        self.assertGreater(n, 0)  # 不崩溃，正常事件已摄入


if __name__ == "__main__":
    unittest.main(verbosity=2)