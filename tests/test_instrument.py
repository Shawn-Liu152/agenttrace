"""v1.2 运行时采集钩子测试：用鸭子类型假客户端验证自动入链（零依赖，不装 SDK）。"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.instrument import (
    instrument_chat_completions, instrument_responses, trace_tool,
    traced_session, to_dict,
)
from agenttrace.store import EvidenceStore


class Obj:
    """最小 SDK 风格对象：支持 model_dump。"""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def model_dump(self):
        return {k: v for k, v in vars(self).items() if not k.startswith("_")}


class FakeCompletions:
    def __init__(self, response=None, exc=None, stream_chunks=None):
        self.response = response
        self.exc = exc
        self.stream_chunks = stream_chunks
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        if kwargs.get("stream"):
            return iter(self.stream_chunks or [])
        return self.response


class FakeResponses:
    def __init__(self, response=None):
        self.response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class FakeClient:
    def __init__(self, chat_resp=None, exc=None, stream_chunks=None,
                 responses_resp=None):
        self.chat = Obj(completions=FakeCompletions(chat_resp, exc, stream_chunks))
        self.responses = FakeResponses(responses_resp)


def _store():
    tmp = tempfile.mkdtemp()
    return EvidenceStore(os.path.join(tmp, "ev.db")), tmp


def _types(store):
    return [e["type"] for e in store.all_events()]


class TestChatInstrument(unittest.TestCase):
    def test_non_stream_records_request_and_response(self):
        resp = Obj(choices=[Obj(message=Obj(content="列目录完成", tool_calls=None))])
        client = FakeClient(chat_resp=resp)
        store, _ = _store()
        instr = instrument_chat_completions(client, store, agent="hermes")
        out = client.chat.completions.create(
            model="gpt-x",
            messages=[{"role": "user", "content": "看看目录"}])
        self.assertIs(out, resp)  # 返回值原样透传
        types = _types(store)
        self.assertIn("session_start", types)
        self.assertIn("user_message", types)
        self.assertIn("agent_message", types)
        texts = [e["content"] for e in store.all_events()
                 if e["type"] == "agent_message"]
        self.assertEqual(texts[-1], "列目录完成")
        instr.restore()
        ok, problems, _ = store.verify()
        self.assertTrue(ok, problems)
        store.close()

    def test_tool_calls_in_response_recorded(self):
        msg = Obj(content=None, tool_calls=[Obj(
            id="c1", function=Obj(name="shell", arguments='{"cmd":"ls"}'))])
        resp = Obj(choices=[Obj(message=msg)])
        client = FakeClient(chat_resp=resp)
        store, _ = _store()
        with instrument_chat_completions(client, store):
            client.chat.completions.create(messages=[])
        names = [e["content"].get("name") for e in store.all_events()
                 if e["type"] == "tool_call"]
        self.assertIn("shell", names)
        store.close()

    def test_exception_recorded_and_reraised(self):
        client = FakeClient(exc=RuntimeError("boom"))
        store, _ = _store()
        with instrument_chat_completions(client, store):
            with self.assertRaises(RuntimeError):
                client.chat.completions.create(messages=[])
        self.assertIn("error", _types(store))
        store.close()

    def test_restore_returns_original(self):
        client = FakeClient(chat_resp=Obj(choices=[]))
        store, _ = _store()
        instr = instrument_chat_completions(client, store)
        # functools.update_wrapper 会在包装函数上打 __wrapped__
        self.assertTrue(hasattr(client.chat.completions.create, "__wrapped__"))
        instr.restore()
        self.assertFalse(hasattr(client.chat.completions.create, "__wrapped__"))
        # 还原后调用仍正常
        client.chat.completions.create(messages=[])
        store.close()

    def test_record_request_false_omits_user(self):
        resp = Obj(choices=[Obj(message=Obj(content="ok", tool_calls=None))])
        client = FakeClient(chat_resp=resp)
        store, _ = _store()
        with instrument_chat_completions(client, store, record_request=False):
            client.chat.completions.create(
                messages=[{"role": "user", "content": "secret"}])
        self.assertNotIn("user_message", _types(store))
        self.assertIn("agent_message", _types(store))
        store.close()

    def test_stream_chunks_passthrough_and_ingested(self):
        chunks = [
            Obj(choices=[Obj(delta=Obj(content="hel"))]),
            Obj(choices=[Obj(delta=Obj(content="lo"))]),
        ]
        client = FakeClient(stream_chunks=chunks)
        store, _ = _store()
        with instrument_chat_completions(client, store):
            got = list(client.chat.completions.create(stream=True, messages=[]))
        self.assertEqual(len(got), 2)  # 逐块原样透传
        texts = [e["content"] for e in store.all_events()
                 if e["type"] == "agent_message"]
        self.assertIn("hello", texts)
        store.close()


class TestResponsesInstrument(unittest.TestCase):
    def test_function_call_item(self):
        resp = Obj(output=[Obj(type="function_call", id="f1", name="shell",
                              arguments='{"cmd":"ls"}')])
        client = FakeClient(responses_resp=resp)
        store, _ = _store()
        with instrument_responses(client, store):
            client.responses.create(input=[])
        self.assertIn("tool_call", _types(store))
        store.close()


class TestTraceTool(unittest.TestCase):
    def test_success_records_call_and_result(self):
        store, _ = _store()

        @trace_tool(store, "shell")
        def shell(cmd):
            return f"ran {cmd}"

        self.assertEqual(shell(cmd="ls"), "ran ls")
        types = _types(store)
        self.assertIn("tool_call", types)
        self.assertIn("tool_result", types)
        call = next(e for e in store.all_events() if e["type"] == "tool_call")
        self.assertEqual(call["content"]["name"], "shell")
        self.assertEqual(call["content"]["arguments"]["cmd"], "ls")
        store.close()

    def test_exception_recorded_and_reraised(self):
        store, _ = _store()

        @trace_tool(store)
        def boom():
            raise ValueError("nope")

        with self.assertRaises(ValueError):
            boom()
        self.assertIn("error", _types(store))
        store.close()

    def test_output_truncation_marked(self):
        store, _ = _store()

        @trace_tool(store, "big", output_limit=10)
        def big():
            return "x" * 100

        big()
        res = [e for e in store.all_events() if e["type"] == "tool_result"][-1]
        self.assertTrue(res["content"].get("truncated"))
        self.assertEqual(len(res["content"]["output"]), 10)
        store.close()


class TestSessionAndToDict(unittest.TestCase):
    def test_traced_session_endpoints(self):
        from agenttrace.recorder import make_user_message
        store, _ = _store()
        with traced_session(store, agent="x") as rec:
            rec.ingest(make_user_message("hi"))
        types = _types(store)
        self.assertEqual(types[0], "session_start")
        self.assertEqual(types[-1], "session_end")
        store.close()

    def test_to_dict_nested(self):
        o = Obj(a=1, child=Obj(b=2), lst=[Obj(c=3)], s="x")
        d = to_dict(o)
        self.assertEqual(d, {"a": 1, "child": {"b": 2}, "lst": [{"c": 3}], "s": "x"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
