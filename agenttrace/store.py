"""AgentTrace SQLite 存储：证据链的持久化与查询。

单文件 SQLite 数据库（evidence.db），表结构：

    events (
        seq INTEGER PRIMARY KEY,   -- 全局序号（链顺序）
        event_id TEXT,             -- 唯一事件 ID
        ts REAL,                   -- 时间戳
        type TEXT,                 -- 事件类型
        actor TEXT,                -- 行为主体
        content TEXT,              -- 内容（JSON）
        meta TEXT,                 -- 元数据（JSON）
        prev_hash TEXT,            -- 链上一条哈希
        hash TEXT,                 -- 本条哈希
    )

    meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )                              -- 会话元信息（agent 身份、模型、工具清单…）

零依赖：sqlite3。
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from .chain import append_event, verify_chain
from .schema import canonical_json

# 延迟导入避免循环依赖（anchor 不依赖 store，可安全前置，但保持显式）
from .anchor import Anchor, AnchorKey  # noqa: E402

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    event_id TEXT,
    ts REAL,
    type TEXT,
    actor TEXT,
    content TEXT,
    meta TEXT,
    prev_hash TEXT,
    hash TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class EvidenceStore:
    def __init__(self, path: str, anchor_key: Optional["AnchorKey"] = None):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()
        self.anchor_key = anchor_key
        self.anchor: Optional[Anchor] = None
        if anchor_key is not None:
            self.anchor = Anchor(path, anchor_key)
        # 批量模式（batch()）：延迟 commit + 链尾缓存 + 锚定合并更新
        self._in_batch = 0
        self._tail_cache: Optional[List[Dict[str, Any]]] = None
        self._anchor_dirty = False

    # ------------------------------------------------------------------
    # 批量模式（v1.0 性能优化：10 万事件从 92s → 秒级）
    # ------------------------------------------------------------------

    @contextmanager
    def batch(self):
        """批量追加：结束统一 commit + 锚定更新一次（O(n) 替代 O(n²)）。

        用法：
            with store.batch():
                for ev in many_events:
                    store.append(ev)
        batch 内外行为一致（append 仍逐条链式哈希、seq 连续），
        只是把 I/O 与锚定签名合并到块尾。**块内抛异常时整体回滚**
        （取证的"全有或全无"语义，复评 v1.0 P2）。
        """
        self._in_batch += 1
        try:
            yield self
        except BaseException:
            # 块内异常：回滚全部未提交数据（取证库不落半截数据）
            self.conn.rollback()
            raise
        finally:
            self._in_batch -= 1
            if self._in_batch == 0:
                self.conn.commit()
                if self.anchor is not None and self._anchor_dirty:
                    self.anchor.update(self.all_events(), self.all_meta())
                    self._anchor_dirty = False
                self._tail_cache = None

    def _maybe_commit(self) -> None:
        if self._in_batch == 0:
            self.conn.commit()

    # ------------------------------------------------------------------
    # 追加
    # ------------------------------------------------------------------

    def _meta_to_db(self, meta: Optional[Dict[str, Any]]) -> Optional[str]:
        """meta → 存储值。无 meta/空 meta 存 NULL（避免空对象读回差异破坏哈希）。"""
        if not meta:
            return None
        if isinstance(meta, dict) and not meta:
            return None
        return canonical_json(meta).decode("utf-8")

    def append(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """追加一条事件（自动链式哈希）。返回完整事件。

        若库已锚定（anchor_key），追加后自动更新锚定签名。
        """
        chain = self.tail_chain()
        ev = append_event(chain, raw_event)
        self._insert_event(ev)
        self._maybe_commit()
        if self._in_batch > 0:
            # 批量：链尾缓存 + 锚定延迟到块尾
            self._tail_cache = [ev]
            if self.anchor is not None:
                self._anchor_dirty = True
        else:
            if self.anchor is not None:
                self.anchor.update(self.all_events(), self.all_meta())
        return ev

    def _insert_event(self, ev: Dict[str, Any]) -> None:
        """插入一条事件；seq 冲突时拒绝覆盖（取证库不允许静默替换）。"""
        try:
            self.conn.execute(
                """INSERT INTO events
                   (seq, event_id, ts, type, actor, content, meta, prev_hash, hash)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    ev["seq"],
                    ev.get("event_id"),
                    ev["ts"],
                    ev["type"],
                    ev["actor"],
                    canonical_json(ev["content"]).decode("utf-8"),
                    self._meta_to_db(ev.get("meta")),
                    ev.get("prev_hash"),
                    ev["hash"],
                ),
            )
        except sqlite3.IntegrityError as e:
            raise ValueError(
                f"拒绝写入: seq={ev['seq']} 已存在（取证库禁止覆盖既有证据）"
            ) from e

    def extend(
        self, events: List[Dict[str, Any]], start_seq: Optional[int] = None
    ) -> int:
        """批量追加已构建好链的事件（通常来自 JSONL 文件）。

        若库内已有事件，会校验 start_seq 衔接；返回写入条数。
        """
        existing = self.count()
        if start_seq is None:
            start_seq = existing
        if start_seq != existing:
            raise ValueError(
                f"序列不衔接: 库内 {existing} 条，导入起始 {start_seq}"
            )
        if not events:
            return 0
        # 先整体验证待导入链的内部一致性
        ok, problems = verify_chain(events)
        if not ok:
            raise ValueError(f"待导入证据链无效: {'; '.join(problems[:5])}")
        # 若库非空，交叉验证衔接点
        if existing > 0:
            tail = self.get(existing - 1)
            head = events[0]
            if head.get("seq") != existing or head.get("prev_hash") != tail["hash"]:
                raise ValueError("待导入链与库内链不衔接（prev_hash 断裂）")
        for ev in events:
            self._insert_event(ev)
        self.conn.commit()
        if self.anchor is not None:
            self.anchor.update(self.all_events(), self.all_meta())
        return len(events)

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def get(self, seq: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM events WHERE seq=?", (seq,)
        ).fetchone()
        return self._row_to_event(row) if row else None

    def tail_chain(self) -> List[Dict[str, Any]]:
        """返回最近一条（或空），用于链式追加。"""
        if self._tail_cache is not None:
            return self._tail_cache
        rows = self.conn.execute(
            "SELECT * FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchall()
        if not rows:
            return []
        return [self._row_to_event(rows[0])]

    def all_events(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        return [self._row_to_event(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ------------------------------------------------------------------
    # 会话元信息
    # ------------------------------------------------------------------

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)",
            (key, canonical_json(value).decode("utf-8")),
        )
        self.conn.commit()
        if self.anchor is not None:
            self.anchor.update(self.all_events(), self.all_meta())

    def get_meta(self, key: str) -> Optional[Any]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        return json.loads(row["value"])

    def all_meta(self) -> Dict[str, Any]:
        rows = self.conn.execute("SELECT key, value FROM meta").fetchall()
        return {r["key"]: json.loads(r["value"]) for r in rows}

    # ------------------------------------------------------------------
    # 验证
    # ------------------------------------------------------------------

    def verify(self) -> tuple[bool, List[str], int]:
        """验证库内整条链 + 外部锚定（若已锚定）。

        返回 (有效, 问题列表, 事件数)。
        未锚定（anchor_key=None）时，仅能检出"事件内部不一致"，
        无法对抗整链重写/末尾截断——verify 会把这一点写进问题列表。
        """
        events = self.all_events()
        ok, problems = verify_chain(events)
        # 复评建议：meta 表为空但事件链非空 → 元信息不受锚定保护，提示补录
        if events and not self.all_meta():
            problems.append(
                "meta 表为空但事件链非空: 会话元信息（agent/model/工具清单）不受锚定保护，"
                "建议用 set_meta 补录后重新锚定"
            )
        if self.anchor is not None:
            aok, aproblems = self.anchor.verify(events, self.all_meta())
            if not aok:
                ok = False
                problems = problems + aproblems
        else:
            problems.append(
                "未锚定（无签名密钥）: 只能检出内部不一致，无法对抗整链重写/末尾截断/元信息篡改"
            )
        return ok, problems, len(events)

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_event(row) -> Dict[str, Any]:
        ev = {
            "seq": row["seq"],
            "ts": row["ts"],
            "type": row["type"],
            "actor": row["actor"],
            "content": json.loads(row["content"]),
        }
        if row["event_id"]:
            ev["event_id"] = row["event_id"]
        if row["meta"]:
            ev["meta"] = json.loads(row["meta"])
        if row["prev_hash"]:
            ev["prev_hash"] = row["prev_hash"]
        if row["hash"]:
            ev["hash"] = row["hash"]
        return ev