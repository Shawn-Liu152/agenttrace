"""Agent 框架适配器（v0.8.0）：把主流 Agent 运行时的事件/消息转成 AgentTrace 证据事件。

设计原则：
  - **零第三方依赖**：本项目红线。适配器不做网络请求、不 import openai/langgraph——
    只做"消息/事件结构 → AgentTrace 事件"的纯转换（dict in, dict out）。
  - 集成方式（用户侧 3 行）：
        client = OpenAI()               # 或任何 Responses API 兼容客户端
        stream = client.responses.create(model="gpt-5", input=[...], stream=True)
        store = EvidenceStore("ev.db", anchor_key=...)
        n = ingest_openai_response_events(store, (e.model_dump() for e in stream))
    OpenAI SDK 事件对象 `.model_dump()` 后与本模块结构一致。
  - LangGraph：从检查点/状态里取 messages 数组喂给 ingest_langgraph_messages。

支持的结构：
  OpenAI Responses API 事件流  → 
    response.created / response.output_item.added (function_call) /
    response.output_text.delta / response.function_call_arguments.delta /
    response.completed / response.output_item.done (function_call_output)
  OpenAI Chat Completions 消息  →  {role, content, tool_calls, tool_call_id}
  LangGraph 状态 messages      →  {type: human|ai|tool|system, content, tool_calls, id}
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, List, Optional, Union

from .recorder import (
    Recorder,
    make_agent_message,
    make_error,
    make_session_start,
    make_tool_call,
    make_tool_result,
    make_user_message,
)
from .store import EvidenceStore

# ---------------------------------------------------------------------------
# 通用：消息数组 → AgentTrace 事件
# ---------------------------------------------------------------------------

# LangGraph 消息 types → AgentTrace types
_LG_TO_AT = {
    "human": "user_message",
    "ai": "agent_message",
    "system": "checkpoint",
    "tool": "tool_result",
}


def _content_to_text(content: Any) -> str:
    """OpenAI/LangGraph content 可能是 str 或 block 列表。"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # OpenAI content blocks: [{type:"text", text:"..."}, {type:"input_text",...}]
        parts = []
        for blk in content:
            if isinstance(blk, dict):
                if blk.get("type") in ("text", "input_text", "output_text"):
                    parts.append(str(blk.get("text", "")))
                elif blk.get("type") == "tool_use":
                    parts.append(json.dumps(blk.get("input", {}), ensure_ascii=False))
                else:
                    parts.append(json.dumps(blk, ensure_ascii=False))
            else:
                parts.append(str(blk))
        return "\n".join(p for p in parts if p)
    return json.dumps(content, ensure_ascii=False)


def _tool_call_to_events(msg: Dict[str, Any], ts: float) -> List[Dict[str, Any]]:
    """一条带 tool_calls 的消息 → 多条 tool_call 事件。OpenAI 与 LangGraph 同构。

    OpenAI:     tool_calls[i] = {id, function: {name, arguments(JSON str)}}
    LangGraph:  tool_calls[i] = {id, name, args(dict)}
    """
    events = []
    for tc in msg.get("tool_calls", []) or []:
        if isinstance(tc, dict):
            name = (tc.get("function") or {}).get("name") or tc.get("name") or "tool"
            args = (tc.get("function") or {}).get("arguments")
            if args is None or args == "":
                args = tc.get("args") or tc.get("input") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args.strip() else {}
                except json.JSONDecodeError:
                    args = {"raw": args}
            ev = make_tool_call(name, args, ts=ts)
            if tc.get("id"):
                _attach_tool_id(ev, tc["id"])
            events.append(ev)
    return events


def _to_events(msg: Dict[str, Any], ts: float) -> List[Dict[str, Any]]:
    """单条消息 → 零到多条 AgentTrace 事件（统一 OpenAI / LangGraph / Chat Completions）。"""
    # LangGraph: type=human/ai/tool/system
    if "type" in msg and msg["type"] in _LG_TO_AT:
        at = _LG_TO_AT[msg["type"]]
        if at == "tool_result":
            name = msg.get("name", "tool")
            content = _content_to_text(msg.get("content", ""))
            return [make_tool_result(name, content, ts=ts)]
        if at == "checkpoint":
            return [make_agent_message("[system] " + _content_to_text(msg.get("content", "")),
                                       ts=ts)]
        if at == "agent_message":
            events: List[Dict[str, Any]] = []
            if msg.get("tool_calls"):
                events += _tool_call_to_events(msg, ts)
            content = _content_to_text(msg.get("content", ""))
            if content:
                events.append(make_agent_message(content, ts=ts))
            return events
        return [make_user_message(_content_to_text(msg.get("content", "")), ts=ts)]

    # OpenAI Chat Completions: role=system/user/assistant/tool (+tool_call_id)
    role = msg.get("role")
    if role == "user":
        return [make_user_message(_content_to_text(msg.get("content", "")), ts=ts)]
    if role == "system":
        return [make_agent_message("[system] " + _content_to_text(msg.get("content", "")), ts=ts)]
    if role == "tool":
        return [make_tool_result(msg.get("name", "tool"),
                                 _content_to_text(msg.get("content", "")), ts=ts)]
    if role == "assistant":
        events = []
        if msg.get("tool_calls"):
            events += _tool_call_to_events(msg, ts)
        content = _content_to_text(msg.get("content", ""))
        if content:
            events.append(make_agent_message(content, ts=ts))
        return events
    return [make_agent_message("[unknown-role] " + json.dumps(msg, ensure_ascii=False), ts=ts)]


def ingest_messages(
    store: EvidenceStore,
    messages: List[Dict[str, Any]],
    agent: str = "agent",
    model: str = "",
    base_ts: Optional[float] = None,
) -> int:
    """把一批框架消息（OpenAI / LangGraph）摄入证据库。返回事件条数。

    自动补 session_start（meta 记 agent/model），并按消息顺序分配递增时间戳。
    """
    n = 0
    r = Recorder(store)
    store.set_meta("agent", agent)
    if model:
        store.set_meta("model", model)
    sev = store.all_events()
    cnt = len(sev)
    if cnt == 0:
        r.ingest(make_session_start(agent=agent, model=model or "unknown",
                                    tools=["adapter"]))
        n += 1
    base = base_ts if base_ts is not None else (time.time() - len(messages))
    for i, msg in enumerate(messages, start=1):
        for ev in _to_events(msg, base + i):
            r.ingest(ev)
            n += 1
    return n


# ---------------------------------------------------------------------------
# OpenAI Responses API 事件流
# ---------------------------------------------------------------------------

# 流式事件类型（不再整体吞掉 done 类，按 item.type 分别处理）
_RESPONSES_TEXT_EVENTS = {"response.output_text.delta",
                          "response.output_text.annotated",
                          "response.completed"}


def _attach_tool_id(ev: Dict[str, Any], tool_id: str) -> None:
    """把工具调用 ID 写入事件 content（顶层字段不入库——store 表无该列）。"""
    if not tool_id:
        return
    c = ev.get("content")
    if isinstance(c, dict):
        c = dict(c)
        c["tool_call_id"] = tool_id
        ev["content"] = c


def _responses_item_name(item: Dict[str, Any]) -> str:
    """从 Responses API output item 里取工具名。"""
    if isinstance(item, str):
        return "tool"
    name = item.get("name") or item.get("tool") or item.get("type")
    if isinstance(name, dict):  # tool 对象
        return name.get("name", "tool")
    return name or "tool"


def ingest_openai_response_events(
    store: EvidenceStore,
    events: Iterable[Dict[str, Any]],
    agent: str = "agent",
    model: str = "",
    meta_from_start: bool = True,
) -> int:
    """摄入 OpenAI Responses API 事件流（每个事件已 .model_dump()）。

    把流式片段合并成完整事件再入链：
      - output_text.delta 累积 → 完成后一条 agent_message
      - function_call_arguments.delta 累积 → 完成后一条 tool_call
      - function_call_output → tool_result
    """
    n = 0
    r = Recorder(store)
    started = store.count() > 0

    # 流状态
    text_buf: List[str] = []
    call_buf: Optional[Dict[str, Any]] = None
    call_args: List[str] = []
    call_id = None
    call_idx = 0
    ts0 = time.time()

    def flush(ts: float) -> None:
        nonlocal text_buf, call_buf, call_args, call_id, call_idx
        if call_buf is not None:
            raw = "".join(call_args)
            try:
                args = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                args = {"raw": raw}
            cc = make_tool_call(call_buf.get("name", "tool"), args, ts=ts)
            if call_id:
                _attach_tool_id(cc, call_id)
            r.ingest(cc)
            call_buf = None
            call_args = []
            call_id = None
        if text_buf:
            r.ingest(make_agent_message("".join(text_buf).strip(), ts=ts))
            text_buf = []

    for raw in events:
        typ = raw.get("type") or raw.get("event")
        if typ in ("response.created",):
            if not started:
                md = (raw.get("response") or {}).get("model")
                if meta_from_start and md:
                    model = model or md
                r.ingest(make_session_start(agent=agent, model=model or "unknown",
                                            tools=["openai-responses"]))
                started = True
            continue
        if typ == "response.output_item.added":
            item = raw.get("item") or {}
            if item.get("type") == "function_call":
                ts = raw.get("ts") or time.time()
                if call_buf is not None:
                    flush(ts)
                call_buf = {"name": _responses_item_name(item), "id": item.get("id")}
                call_id = item.get("id")
                call_idx = raw.get("output_index", 0)
                args = item.get("arguments")
                if isinstance(args, str) and args:
                    call_args = [args]
            continue
        if typ == "response.output_item.done":
            item = raw.get("item") or {}
            itype = item.get("type")
            if itype == "function_call":
                # 工具调用完整结束（部分流会在 done 才给全 arguments）
                ts = raw.get("ts") or time.time()
                if call_buf is not None:
                    flush(ts)
                name = _responses_item_name(item)
                raw_args = item.get("arguments") or ""
                try:
                    args = json.loads(raw_args) if raw_args else {}
                except json.JSONDecodeError:
                    args = {"raw": raw_args}
                cc = make_tool_call(name, args, ts=ts)
                if item.get("id"):
                    _attach_tool_id(cc, item["id"])
                r.ingest(cc)
            elif itype == "function_call_output":
                ts = raw.get("ts") or time.time()
                flush(ts)  # 先清 pending 文本/调用
                output = item.get("output", "")
                if isinstance(output, list):
                    output = json.dumps(output, ensure_ascii=False)
                tr = make_tool_result("tool", str(output), ts=ts)
                if item.get("id"):
                    _attach_tool_id(tr, item["id"])
                r.ingest(tr)
            continue
        if typ in _RESPONSES_TEXT_EVENTS:
            # 文本 delta 累积
            delta = raw.get("delta") or (raw.get("output_text") or "")
            if isinstance(delta, str) and delta:
                text_buf.append(delta)
            elif isinstance(delta, dict):
                if delta.get("type") == "text":
                    text_buf.append(delta.get("text", ""))
            if typ == "response.completed":
                flush(raw.get("ts") or time.time())
            continue
        if typ == "response.function_call_arguments.delta":
            delta = raw.get("delta", "")
            call_args.append(delta if isinstance(delta, str) else str(delta))
            continue
        # 未识别事件：静默跳过（流式事件很多，不能打断采集）
    # 流结束兜底 flush
    flush(time.time())
    return store.count() - (0 if started else 0)


# ---------------------------------------------------------------------------
# LangGraph
# ---------------------------------------------------------------------------

def ingest_langgraph_state(
    store: EvidenceStore,
    messages: List[Dict[str, Any]],
    agent: str = "agent",
    model: str = "",
) -> int:
    """摄入 LangGraph 状态里的 messages（checkpoint 恢复/离线导入）。

    LangGraph 消息形如: {type: "human"|"ai"|"tool"|"system", content: str|blocks,
                          tool_calls: [...], name: "tool名", id: ...}
    """
    return ingest_messages(store, messages, agent=agent, model=model)