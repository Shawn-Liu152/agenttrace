"""AgentTrace 事件模型：标准化的 Agent 行为事件定义。"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 事件类型
# ---------------------------------------------------------------------------

EVENT_TYPES = {
    "session_start",    # 会话开始（含 Agent 身份、模型、工具清单）
    "user_message",     # 用户输入
    "agent_message",    # Agent 文本回复
    "tool_call",        # Agent 发起工具调用
    "tool_result",      # 工具返回结果
    "error",            # 错误/异常
    "checkpoint",       # 人工检查点/里程碑
    "session_end",      # 会话结束
}

# 允许的 actor（行为主体）
ACTORS = {"user", "agent", "tool", "system"}

# 必填字段：每条事件必须有这些键（seq 由链构建方自动分配，非必填）
REQUIRED_KEYS = {"ts", "type", "actor", "content"}

# 可选元数据字段
OPTIONAL_KEYS = {"meta", "prev_hash", "hash", "event_id"}


class SchemaError(ValueError):
    """事件不符合 schema 时的异常。"""


def now_ts() -> float:
    return time.time()


def new_event_id() -> str:
    return uuid.uuid4().hex


def validate_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    """校验并规范化一条事件。

    返回规范化后的副本；非法事件抛 SchemaError（带具体原因）。
    """
    if not isinstance(ev, dict):
        raise SchemaError("event 必须是 dict")

    missing = REQUIRED_KEYS - set(ev)
    if missing:
        raise SchemaError(f"缺少必填字段: {sorted(missing)}")

    # seq 非负整数（缺省时由链构建方分配）
    seq = ev.get("seq")
    if seq is not None and (not isinstance(seq, int) or seq < 0):
        raise SchemaError(f"seq 必须是非负整数: {seq!r}")

    # ts 数值时间戳
    ts = ev["ts"]
    if not isinstance(ts, (int, float)):
        raise SchemaError(f"ts 必须是数值时间戳: {ts!r}")

    # type / actor 枚举
    if ev["type"] not in EVENT_TYPES:
        raise SchemaError(f"未知事件类型: {ev['type']!r}，允许: {sorted(EVENT_TYPES)}")
    if ev["actor"] not in ACTORS:
        raise SchemaError(f"未知 actor: {ev['actor']!r}，允许: {sorted(ACTORS)}")

    # content 可以是任意 JSON 值（str/dict/list/None），但不能缺失
    # （REQUIRED_KEYS 已保证存在）

    # meta 必须是 dict（如果提供）
    if "meta" in ev and ev["meta"] is not None and not isinstance(ev["meta"], dict):
        raise SchemaError("meta 必须是 dict 或 null")

    # 规范化：固定键顺序，便于哈希
    out: Dict[str, Any] = {}
    for k in ("ts", "type", "actor", "content"):
        out[k] = ev[k]
    if seq is not None:
        out["seq"] = seq
    if "meta" in ev and ev["meta"] is not None:
        out["meta"] = ev["meta"]
    if "event_id" in ev and ev["event_id"]:
        out["event_id"] = ev["event_id"]
    return out


def canonical_json(obj: Any) -> bytes:
    """将任意 JSON 对象序列化为规范字节（排序键、无空格），用于哈希。"""
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")