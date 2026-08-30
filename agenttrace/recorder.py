"""AgentTrace 采集器：把 Agent 运行日志（JSONL 或实时流）摄入证据库。

两种模式：
  1. 离线批量：读 JSONL 文件（每条一行事件 dict），校验 + 链式哈希后入库
  2. 实时流：从 stdin 逐行读取（Agent 运行时边跑边写），追加进同一证据链

JSONL 事件格式（每行一个 JSON 对象）:
    {"seq": 0, "ts": 1725000000.123, "type": "session_start",
     "actor": "system", "content": {"agent": "hermes", "model": "..."}}
    {"seq": 1, "ts": ..., "type": "tool_call", "actor": "agent",
     "content": {"name": "terminal", "arguments": {"command": "ls"}}}

注意：seq 会由 recorder 自动重新编号（以库内链尾为起点），
保证链连续；外部传入的 seq 仅作参考。
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Iterable, List, Optional

from .schema import validate_event, new_event_id, now_ts
from .store import EvidenceStore


class Recorder:
    """采集器：持有 EvidenceStore，逐条摄入事件。"""

    def __init__(self, store: EvidenceStore):
        self.store = store
        # 以库内链尾为起点编号
        self._next_seq = store.count()

    def ingest(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """摄入一条事件（自动补 seq/event_id 并链式哈希）。"""
        ev = validate_event(raw)
        ev["seq"] = self._next_seq
        if not ev.get("event_id"):
            ev["event_id"] = new_event_id()
        self._next_seq += 1
        return self.store.append(ev)

    def ingest_jsonl(self, lines: Iterable[str]) -> int:
        """摄入 JSONL 流（可迭代的行）。返回成功条数。"""
        n = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"非法 JSON 行: {e}") from e
            self.ingest(raw)
            n += 1
        return n

    def ingest_jsonl_file(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as f:
            return self.ingest_jsonl(f)

    def ingest_stdin(self) -> int:
        """从 stdin 逐行读取（实时流模式）。"""
        return self.ingest_jsonl(sys.stdin)


def make_session_start(
    agent: str = "unknown",
    model: str = "",
    tools: Optional[List[str]] = None,
    ts: Optional[float] = None,
) -> Dict[str, Any]:
    """便捷构造 session_start 事件。"""
    return {
        "seq": 0,
        "ts": ts if ts is not None else now_ts(),
        "type": "session_start",
        "actor": "system",
        "content": {
            "agent": agent,
            "model": model,
            "tools": tools or [],
        },
    }


def make_tool_call(
    name: str, arguments: Dict[str, Any], ts: Optional[float] = None
) -> Dict[str, Any]:
    return {
        "ts": ts if ts is not None else now_ts(),
        "type": "tool_call",
        "actor": "agent",
        "content": {"name": name, "arguments": arguments},
    }


def make_tool_result(
    name: str, output: str, ok: bool = True, ts: Optional[float] = None
) -> Dict[str, Any]:
    return {
        "ts": ts if ts is not None else now_ts(),
        "type": "tool_result",
        "actor": "tool",
        "content": {"name": name, "ok": ok, "output": output},
    }


def make_user_message(text: str, ts: Optional[float] = None) -> Dict[str, Any]:
    return {
        "ts": ts if ts is not None else now_ts(),
        "type": "user_message",
        "actor": "user",
        "content": text,
    }


def make_agent_message(text: str, ts: Optional[float] = None) -> Dict[str, Any]:
    return {
        "ts": ts if ts is not None else now_ts(),
        "type": "agent_message",
        "actor": "agent",
        "content": text,
    }


def make_error(text: str, ts: Optional[float] = None) -> Dict[str, Any]:
    return {
        "ts": ts if ts is not None else now_ts(),
        "type": "error",
        "actor": "system",
        "content": text,
    }


def make_session_end(
    summary: str = "", ts: Optional[float] = None, meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    ev = {
        "ts": ts if ts is not None else now_ts(),
        "type": "session_end",
        "actor": "system",
        "content": {"summary": summary},
    }
    if meta:
        ev["meta"] = meta
    return ev