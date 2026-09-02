"""真实 Agent 运行时采集钩子（v1.2.0，零依赖）。

`adapters.py` 解决"数据已经拿到 → 证据事件"的纯转换；本模块解决
"怎么自动拿到数据"——**不改 Agent 业务代码、不 import 任何 SDK**，用鸭子
类型在运行时包装：

  - OpenAI 兼容客户端的 `chat.completions.create` / `responses.create`
    （OpenAI 官方 SDK、vLLM、ollama-python、各类兼容网关同构）：请求消息
    与响应消息自动入证据链，异常记 error 后原样抛出；
  - 任意工具函数（shell、检索、内部 API）：装饰器自动记 tool_call /
    tool_result / error。

设计原则与 adapters 一致：本模块不 import openai、不做网络请求，只认
"有这些属性/方法就能包"的结构化对象（model_dump / __dict__ / dict）。

典型用法（3 行接入）：

    from openai import OpenAI
    from agenttrace.store import EvidenceStore
    from agenttrace.instrument import instrument_chat_completions, trace_tool

    store = EvidenceStore("ev.db", anchor_key=...)
    client = OpenAI()
    instrument_chat_completions(client, store, agent="hermes", model="gpt-x")
    # 之后每次 client.chat.completions.create(...) 自动入链，返回值不变

    @trace_tool(store, "shell")
    def shell(cmd): ...
"""

from __future__ import annotations

import functools
import json
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, List, Optional

from .adapters import ingest_messages
from .recorder import Recorder, make_error, make_tool_call, make_tool_result
from .store import EvidenceStore


# ---------------------------------------------------------------------------
# 通用：点路径 getattr/setattr、对象 → dict 归一化
# ---------------------------------------------------------------------------


def _resolve(obj: Any, path: str):
    cur = obj
    for part in path.split("."):
        cur = getattr(cur, part)
    return cur


def _assign(obj: Any, path: str, value: Any) -> None:
    parts = path.split(".")
    parent = obj
    for part in parts[:-1]:
        parent = getattr(parent, part)
    setattr(parent, parts[-1], value)


def to_dict(obj: Any) -> Any:
    """SDK 对象 → 纯 dict/list（model_dump 优先，其次 __dict__，dict 原样）。"""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_dict(v) for v in obj]
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            return to_dict(dump())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return {k: to_dict(v) for k, v in vars(obj).items()
                if not k.startswith("_")}
    return str(obj)


# ---------------------------------------------------------------------------
# OpenAI 兼容客户端包装
# ---------------------------------------------------------------------------


def _response_chat_messages(resp_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Chat Completions 响应 → OpenAI 消息 dict 列表（喂给 ingest_messages）。"""
    out: List[Dict[str, Any]] = []
    choices = resp_dict.get("choices") or []
    for ch in choices:
        msg = ch.get("message") or {}
        if not msg:
            continue
        m: Dict[str, Any] = {"role": "assistant"}
        if msg.get("content"):
            m["content"] = msg["content"]
        if msg.get("tool_calls"):
            m["tool_calls"] = to_dict(msg["tool_calls"])
        out.append(m)
    return out


def _response_responses_messages(resp_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Responses API 响应 → 消息/工具调用事件列表。"""
    out: List[Dict[str, Any]] = []
    for item in resp_dict.get("output") or []:
        itype = item.get("type")
        if itype == "message":
            texts = []
            for blk in item.get("content", []) or []:
                if isinstance(blk, dict) and blk.get("text"):
                    texts.append(blk["text"])
            if texts:
                out.append({"role": "assistant", "content": "\n".join(texts)})
        elif itype in ("function_call", "custom_tool_call"):
            args = item.get("arguments") or item.get("input") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"raw": args}
            out.append({"role": "assistant",
                        "tool_calls": [{"id": item.get("id", ""),
                                        "function": {"name": item.get("name", "tool"),
                                                     "arguments": json.dumps(args)}}]})
    return out


class Instrumentation:
    """包装句柄：restore() 还原原方法；也可作 context manager。"""

    def __init__(self, client: Any, path: str, original: Callable):
        self._client = client
        self._path = path
        self._original = original
        self.active = True

    def restore(self) -> None:
        if self.active:
            _assign(self._client, self._path, self._original)
            self.active = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.restore()
        return False


def _wrap_create(client: Any, store: EvidenceStore, path: str,
                 responder: Callable[[Dict[str, Any]], List[Dict[str, Any]]],
                 agent: str, model: str, record_request: bool) -> Instrumentation:
    original = _resolve(client, path)
    recorder = Recorder(store)

    def wrapped(*args, **kwargs):
        # 绝不能改传给原 SDK 方法的 kwargs（messages/model 都是它的必需参数）
        req_messages = kwargs.get("messages")
        model_name = kwargs.get("model") or model
        batch: List[Dict[str, Any]] = []
        if record_request and isinstance(req_messages, list):
            batch.extend(to_dict(req_messages))

        def _ingest_response(resp_obj: Any) -> Any:
            resp_dict = to_dict(resp_obj)
            if isinstance(resp_dict, dict):
                if model_name:
                    store.set_meta("model", str(model_name))
                batch.extend(responder(resp_dict))
                if batch:
                    ingest_messages(store, batch, agent=agent, model=str(model_name))
            return resp_obj

        try:
            if kwargs.get("stream"):
                return _stream_iter(original(*args, **kwargs), _ingest_response)
            resp = original(*args, **kwargs)
            return _ingest_response(resp)
        except Exception as e:
            recorder.ingest(make_error(f"{path} 调用异常: {type(e).__name__}: {e}"))
            raise

    functools.update_wrapper(wrapped, original, updated=())
    _assign(client, path, wrapped)
    return Instrumentation(client, path, original)


def _stream_iter(stream: Any, on_finish: Callable[[Any], Any]) -> Iterator[Any]:
    """流式响应：逐块透传（不改变消费方式），结束时把聚合响应交给回调。

    主流 SDK 的流是可迭代对象，chunk 可 model_dump；这里做鸭子类型聚合，
    不假设具体类。不支持的流形态原样返回（不阻断业务，降级静默不抛错）。
    """
    chunks: List[Dict[str, Any]] = []
    try:
        for chunk in stream:
            chunks.append(to_dict(chunk))
            yield chunk
    finally:
        if chunks:
            merged = {"output": [], "choices": []}
            # Chat 流：拼 delta 文本
            text_buf: List[str] = []
            for c in chunks:
                for ch in c.get("choices", []) or []:
                    delta = ch.get("delta") or {}
                    if isinstance(delta.get("content"), str):
                        text_buf.append(delta["content"])
            if text_buf:
                merged["choices"] = [{"message": {"role": "assistant",
                                                  "content": "".join(text_buf)}}]
                try:
                    on_finish(merged)
                except Exception:
                    pass  # 采集失败不影响业务流（降级纪律：不静默改返回值）


def instrument_chat_completions(client: Any, store: EvidenceStore,
                                agent: str = "agent", model: str = "",
                                record_request: bool = True) -> Instrumentation:
    """包装 client.chat.completions.create：每次调用自动入证据链。

    record_request=False 时只记录模型响应（请求消息可能含敏感原文的场景）。
    返回 Instrumentation，.restore() 还原。
    """
    return _wrap_create(client, store, "chat.completions.create",
                        _response_chat_messages, agent, model, record_request)


def instrument_responses(client: Any, store: EvidenceStore,
                         agent: str = "agent", model: str = "",
                         record_request: bool = True) -> Instrumentation:
    """包装 client.responses.create（OpenAI Responses API 兼容客户端）。"""
    return _wrap_create(client, store, "responses.create",
                        _response_responses_messages, agent, model, record_request)


# ---------------------------------------------------------------------------
# 工具函数装饰器
# ---------------------------------------------------------------------------


def trace_tool(store: EvidenceStore, name: Optional[str] = None,
               output_limit: int = 4000):
    """装饰器：工具函数调用自动记 tool_call → tool_result/error。

    output_limit: 工具输出入库截断长度（证据链不追求大字段全量，超限标注）。
    异常路径记 error 事件后原样抛出，不吞异常。
    """
    def deco(fn: Callable):
        tool_name = name or getattr(fn, "__name__", "tool")

        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            rec = Recorder(store)
            safe_args: Dict[str, Any] = {}
            if args:
                safe_args["args"] = [_safe(v) for v in args]
            if kwargs:
                safe_args.update({k: _safe(v) for k, v in kwargs.items()})
            rec.ingest(make_tool_call(tool_name, safe_args))
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                rec.ingest(make_error(f"工具 {tool_name} 异常: {type(e).__name__}: {e}"))
                raise
            text = result if isinstance(result, str) else json.dumps(
                to_dict(result), ensure_ascii=False, default=str)
            truncated = False
            if len(text) > output_limit:
                text, truncated = text[:output_limit], True
            ev = make_tool_result(tool_name, text)
            if truncated:
                ev["content"]["truncated"] = True
            rec.ingest(ev)
            return result
        return wrapped
    return deco


def _safe(v: Any) -> Any:
    """参数归一化（对象转 dict，基本类型原样）。"""
    return to_dict(v)


@contextmanager
def traced_session(store: EvidenceStore, agent: str = "agent",
                   model: str = "", tools: Optional[List[str]] = None):
    """上下文管理器：进入确保 session_start，离开写 session_end。"""
    from .recorder import make_session_end, make_session_start
    rec = Recorder(store)
    if store.count() == 0:
        rec.ingest(make_session_start(agent=agent, model=model or "unknown",
                                      tools=tools or []))
    try:
        yield rec
    finally:
        rec.ingest(make_session_end("session closed by traced_session"))
