"""AgentTrace 外部锚定（anchor）：链尾承诺签名，堵截哈希链的自洽性盲区。

问题：SHA-256 哈希链只能证明"数据内部自洽"，无法对抗"拥有数据库写权限
的攻击者重写整条链 / 截断末尾 / 篡改链外元信息"。任何事件都在库内，
攻击者可以读出 → 修改 → 从 seq 0 重算 → 回写，verify 照样通过。

锚定方案（零依赖，HMAC-SHA256）：
  - 每次追加后，把 (genesis_hash, seq_max, tip_hash, meta_hash) 序列化后用
    HMAC-SHA256 签名，写入独立的锚定文件 <db>.anchor.json
  - 签名密钥存独立文件（建议与数据库分开放置 / 环境变量注入）
  - verify 时重新计算并比对：
      * 库内链尾与锚定 tip 不一致        → 末尾截断/追加伪造 → 检出
      * 整链重算后 tip 变了但锚定没变    → 整链重写         → 检出
      * meta 哈希与锚定不一致            → 元信息篡改       → 检出
      * 整库被另一条链替换，genesis 不同  → 整体替换         → 检出
  - 攻击者要绕过必须同时拿到密钥重签——这正是外部锚定的意义

密钥管理注意（README 有详细说明）：
  - 密钥与数据库分开存储；条件允许时放在另一台机器/HSM
  - 密钥丢失 = 证据链完整性无法再验证（这是安全信号，不是 bug）
  - 生产环境可升级为 Ed25519 签名或 RFC3161 时间戳（架构兼容）
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional

from .schema import canonical_json

ANCHOR_SUFFIX = ".anchor.json"
KEY_SUFFIX = ".anchor.key"  # 旧版默认（与数据库同目录）——仅兼容迁移用

GENESIS_FIELD = "genesis_hash"
SEQ_FIELD = "seq_max"
TIP_FIELD = "tip_hash"
META_FIELD = "meta_hash"
TS_FIELD = "anchored_at"
MAC_FIELD = "mac"
VERSION_FIELD = "version"

VERSION = 1


def _key_root() -> str:
    """密钥配置根目录：与数据库分离（Windows %APPDATA%\agenttrace\keys，
    POSIX ~/.config/agenttrace/keys）。"""
    import os as _os

    if _os.name == "nt":
        base = _os.environ.get("APPDATA") or _os.path.expanduser("~")
        return _os.path.join(base, "agenttrace", "keys")
    base = _os.environ.get("XDG_CONFIG_HOME") or _os.path.expanduser("~/.config")
    return _os.path.join(base, "agenttrace", "keys")


def tip_hash_of(events: list) -> Optional[str]:
    """链尾事件哈希（空链返回 None）。"""
    if not events:
        return None
    return events[-1]["hash"]


def genesis_hash_of(events: list) -> Optional[str]:
    if not events:
        return None
    return events[0]["hash"]


def meta_hash_of(meta: Dict[str, Any]) -> str:
    """meta 表的规范哈希（纳入锚定，防元信息篡改）。"""
    return hashlib.sha256(canonical_json(meta)).hexdigest()


def _mac(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _payload(genesis: Optional[str], seq_max: int, tip: Optional[str], meta_hash: str) -> bytes:
    return canonical_json({
        GENESIS_FIELD: genesis,
        SEQ_FIELD: seq_max,
        TIP_FIELD: tip,
        META_FIELD: meta_hash,
    })


def anchor_path_for(db_path: str) -> str:
    return db_path + ANCHOR_SUFFIX


def key_path_for(db_path: str) -> str:
    """新默认密钥路径：独立于数据库（用户配置目录，按 db 路径哈希命名）。

    与数据库分离是安全前提——密钥与库同目录 = 拿到库的写权限者
    同时拿到密钥，可重签锚定、抹掉一切痕迹。
    """
    import hashlib as _hashlib

    digest = _hashlib.sha256(db_path.encode("utf-8")).hexdigest()[:12]
    basename = os.path.basename(db_path) or "evidence"
    return os.path.join(_key_root(), f"{basename}.{digest}.key")


def legacy_key_path_for(db_path: str) -> str:
    """v0.1/v0.2 旧版密钥路径（与库同目录）——仅用于兼容迁移。"""
    return db_path + KEY_SUFFIX


def resolve_key_path(db_path: str) -> str:
    """实际使用的密钥路径：优先新位置；旧位置存在则返回旧位置（并提示迁移）。"""
    new_path = key_path_for(db_path)
    if os.path.exists(new_path):
        return new_path
    legacy = legacy_key_path_for(db_path)
    if os.path.exists(legacy):
        return legacy
    return new_path


class AnchorKey:
    """签名密钥（32 字节 HMAC 密钥）。"""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"锚定密钥必须为 32 字节，实际 {len(key)}")
        self.key = key

    @classmethod
    def generate(cls) -> "AnchorKey":
        return cls(secrets.token_bytes(32))

    @classmethod
    def load(cls, key_path: str) -> "AnchorKey":
        raw = open(key_path, "rb").read()
        return cls(raw)

    @classmethod
    def from_hex(cls, hex_str: str) -> "AnchorKey":
        return cls(bytes.fromhex(hex_str.strip()))

    def hex(self) -> str:
        return self.key.hex()

    def save(self, key_path: str) -> str:
        """写密钥文件（POSIX 0600；Windows 上尽力设置只读）。"""
        with open(key_path, "wb") as f:
            f.write(self.key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key_path


class Anchor:
    """证据库的外部锚定。绑定一个 EvidenceStore 和一个 AnchorKey。"""

    def __init__(self, db_path: str, key: AnchorKey):
        self.db_path = db_path
        self.key = key
        self.path = anchor_path_for(db_path)

    # ------------------------------------------------------------------
    # 签名 / 校验核心
    # ------------------------------------------------------------------

    @staticmethod
    def _mac_of(key: bytes, payload: bytes) -> str:
        return _mac(key, payload)

    def sign(self, events: list, meta: Dict[str, Any]) -> Dict[str, Any]:
        """对当前链状态生成锚定记录。"""
        genesis = genesis_hash_of(events)
        tip = tip_hash_of(events)
        seq_max = events[-1]["seq"] if events else -1
        mh = meta_hash_of(meta)
        payload = _payload(genesis, seq_max, tip, mh)
        return {
            VERSION_FIELD: VERSION,
            GENESIS_FIELD: genesis,
            SEQ_FIELD: seq_max,
            TIP_FIELD: tip,
            META_FIELD: mh,
            TS_FIELD: time.time(),
            MAC_FIELD: hmac.new(self.key.key, payload, hashlib.sha256).hexdigest(),
        }

    def update(self, events: list, meta: Dict[str, Any]) -> Dict[str, Any]:
        """签名并写盘（原子写：先写临时文件再替换）。"""
        record = self.sign(events, meta)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)
        os.replace(tmp, self.path)
        return record

    # ------------------------------------------------------------------
    # 验证
    # ------------------------------------------------------------------

    def verify(self, events: list, meta: Dict[str, Any]) -> tuple[bool, list[str]]:
        """验证库内链状态与锚定一致。返回 (有效, 问题列表)。"""
        problems: list[str] = []
        if not os.path.exists(self.path):
            return False, ["锚定文件不存在（证据库从未锚定，无法对抗整链重写/末尾截断）"]

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                record = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return False, [f"锚定文件损坏: {e}"]

        # 1) MAC 校验：锚定记录本身是否被篡改
        mac = record.pop("mac", None)
        if mac is None:
            return False, ["锚定记录缺少 mac"]
        expected_mac = hmac.new(
            self.key.key,
            _payload(record.get(GENESIS_FIELD), record.get(SEQ_FIELD, -1),
                     record.get(TIP_FIELD), record.get(META_FIELD, "")),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            return False, ["锚定签名校验失败（锚定记录被篡改，或密钥不匹配）"]

        # 2) genesis 校验：整库替换检测
        cur_genesis = genesis_hash_of(events)
        if cur_genesis != record.get(GENESIS_FIELD):
            problems.append(f"genesis 哈希不匹配（整条链被替换）: 库 {cur_genesis} vs 锚定 {record.get(GENESIS_FIELD)}")

        # 3) seq_max 校验：末尾截断/追加检测
        cur_seq_max = events[-1]["seq"] if events else -1
        if cur_seq_max != record.get(SEQ_FIELD):
            problems.append(f"链尾 seq 不匹配（末尾截断或被追加伪造）: 库 {cur_seq_max} vs 锚定 {record.get(SEQ_FIELD)}")

        # 4) tip 校验：内容重写检测
        cur_tip = tip_hash_of(events)
        if cur_tip != record.get(TIP_FIELD):
            problems.append("链尾哈希不匹配（事件内容被改写）")

        # 5) meta 校验：元信息篡改检测
        cur_mh = meta_hash_of(meta)
        if cur_mh != record.get(META_FIELD):
            problems.append("meta 哈希不匹配（会话元信息被篡改）")

        return not problems, problems


def ensure_key(db_path: str, key_path: Optional[str] = None) -> AnchorKey:
    """获取密钥：给定路径存在则加载；否则生成并写入密钥文件。

    优先顺序：
      1. 显式 key_path 参数
      2. 环境变量 AGENTTRACE_ANCHOR_KEY_HEX（hex 密钥）/
         AGENTTRACE_ANCHOR_KEY_PATH（密钥文件路径）
      3. 新默认位置（用户配置目录，与数据库分离）
      4. 旧位置 <db>.anchor.key 存在则复用（兼容迁移）
    """
    if key_path is None:
        key_path = os.environ.get("AGENTTRACE_ANCHOR_KEY_PATH")
    hex_env = os.environ.get("AGENTTRACE_ANCHOR_KEY_HEX")
    if hex_env:
        return AnchorKey.from_hex(hex_env)
    if key_path is None:
        key_path = resolve_key_path(db_path)
    if os.path.exists(key_path):
        return AnchorKey.load(key_path)
    # 新目录不存在则创建
    key_dir = os.path.dirname(key_path)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)
    key = AnchorKey.generate()
    key.save(key_path)
    return key


def anchor_state(db_path: str) -> Dict[str, Any]:
    """检查 db 的锚定/密钥状态（供 CLI 分级输出）。返回:
    {
      "has_anchor_file": bool,   # 锚定文件存在
      "key_available": bool,     # 能找到密钥（新位置/旧位置/环境变量）
      "key_location": str,       # "config-dir" / "legacy"(与库同目录) / "env" / "missing" / "explicit"
      "anchor_ok": Optional[bool],  # 若可验证，锚定是否有效
      "problems": [str],
    }
    """
    import os as _os

    anchor_path = anchor_path_for(db_path)
    has_anchor = _os.path.exists(anchor_path)
    key_available = False
    key_location = "missing"

    if _os.environ.get("AGENTTRACE_ANCHOR_KEY_HEX"):
        key_available, key_location = True, "env"
    elif _os.environ.get("AGENTTRACE_ANCHOR_KEY_PATH") and _os.path.exists(
        _os.environ["AGENTTRACE_ANCHOR_KEY_PATH"]
    ):
        key_available, key_location = True, "explicit"
    elif _os.path.exists(key_path_for(db_path)):
        key_available, key_location = True, "config-dir"
    elif _os.path.exists(legacy_key_path_for(db_path)):
        key_available, key_location = True, "legacy"

    return {
        "has_anchor_file": has_anchor,
        "key_available": key_available,
        "key_location": key_location,
        "anchor_ok": None,
        "problems": [],
    }