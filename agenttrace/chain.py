"""AgentTrace 哈希链：将事件序列绑定为防篡改的证据链。

每条事件记录其内容的 SHA-256 哈希，并包含上一条事件的哈希（prev_hash），
形成链式结构。任何一条事件被修改（哪怕一个字节），其 hash 变化，
导致后续所有事件的 prev_hash 不匹配 —— 篡改可被立即检测。

    链式结构:
        ev[0].hash   = sha256(canonical(ev[0] 去掉 prev_hash/hash))
        ev[i].hash   = sha256(canonical(ev[i] 去掉 prev_hash/hash) + ev[i-1].hash)
        ev[i].prev_hash = ev[i-1].hash
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from .schema import canonical_json, validate_event


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strip_link_fields(ev: Dict[str, Any]) -> Dict[str, Any]:
    """去掉链字段，得到"事件本体"（用于哈希）。"""
    return {k: v for k, v in ev.items() if k not in ("prev_hash", "hash")}


def hash_event(ev: Dict[str, Any], prev_hash: Optional[str]) -> str:
    """计算单条事件的哈希。若 prev_hash 提供，则纳入链式绑定。"""
    body = canonical_json(_strip_link_fields(ev))
    if prev_hash:
        return digest(body + b"|" + prev_hash.encode("ascii"))
    return digest(body)


def verify_chain(events: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """验证整条证据链。

    返回 (是否完整有效, 问题列表)。问题为空 => 链完整。
    检查项：
      1. 每条事件的 hash 字段与重算值一致（内容未被篡改）
      2. 每条事件的 prev_hash 指向上一条的 hash（链接未被破坏）
      3. 事件 seq 连续（没有事件被删除）
    """
    problems: List[str] = []

    if not events:
        return True, []

    # seq 连续性
    seqs = [ev.get("seq") for ev in events]
    for i, s in enumerate(seqs):
        if s != i:
            problems.append(f"seq 不连续: 位置 {i} 期望 {i}，实际 {s}")

    prev = None
    for i, ev in enumerate(events):
        # 校验 hash 字段
        stored_hash = ev.get("hash")
        if stored_hash is None:
            problems.append(f"[{i}] 缺少 hash 字段")
            continue
        recomputed = hash_event(ev, prev)
        if stored_hash != recomputed:
            problems.append(f"[{i}] 内容哈希不匹配（事件被篡改或链被破坏）: "
                            f"存储 {stored_hash} vs 重算 {recomputed}")
        # 校验 prev_hash
        stored_prev = ev.get("prev_hash")
        if i == 0:
            if stored_prev not in (None, ""):
                problems.append(f"[0] 首条事件不应有 prev_hash: {stored_prev}")
        else:
            if stored_prev != prev:
                problems.append(f"[{i}] prev_hash 不匹配（链接断裂）: "
                                f"存储 {stored_prev} vs 期望 {prev}")
        prev = stored_hash or recomputed

    return not problems, problems


def append_event(
    chain: List[Dict[str, Any]], raw_event: Dict[str, Any]
) -> Dict[str, Any]:
    """向链尾追加一条事件，自动计算 seq/prev_hash/hash。

    raw_event 会被校验并规范化；返回的完整事件可直接入库。
    """
    ev = validate_event(raw_event)
    if "seq" not in ev:
        ev["seq"] = (chain[-1]["seq"] + 1) if chain else 0
    prev_hash = chain[-1]["hash"] if chain else None
    ev["prev_hash"] = prev_hash
    ev["hash"] = hash_event(ev, prev_hash)
    return ev


def load_chain_from_jsonl(path: str) -> List[Dict[str, Any]]:
    """从 JSONL 文件读取事件链。"""
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events