"""Ed25519 外部锚定（v0.4.0）：非对称签名锚定，解决 HMAC 的信任根矛盾。

HMAC（v0.2-v0.3）：验证者必须持有签名密钥 → 密钥放哪都两难。
Ed25519（v0.4）：**私钥只在签名端（Agent 侧），公钥可自由分发给任何验证者**。
验证端被攻破也只能"验证"，无法伪造——信任根从共享秘密升级为单向能力。

锚定记录格式（<db>.anchor.json，version=2）：
    {
      "version": 2,
      "algo": "ed25519",
      "public_key": "<64 hex>",     # 公钥内嵌（验证端无需额外配置）
      "genesis_hash": "...",
      "seq_max": N,
      "tip_hash": "...",
      "meta_hash": "...",
      "anchored_at": ts,
      "signature": "<128 hex>"      # 对规范化 payload 的 Ed25519 签名
    }
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

from . import ed25519
from .schema import canonical_json
from .anchor import genesis_hash_of, tip_hash_of
import hashlib

VERSION = 2
ALGO = "ed25519"

GENESIS_FIELD = "genesis_hash"
SEQ_FIELD = "seq_max"
TIP_FIELD = "tip_hash"
META_FIELD = "meta_hash"
TS_FIELD = "anchored_at"
SIG_FIELD = "signature"
PK_FIELD = "public_key"
VERSION_FIELD = "version"
ALGO_FIELD = "algo"


def _signed_payload(genesis: Optional[str], seq_max: int, tip: Optional[str], meta_hash: str) -> bytes:
    return canonical_json({
        GENESIS_FIELD: genesis,
        SEQ_FIELD: seq_max,
        TIP_FIELD: tip,
        META_FIELD: meta_hash,
    })


def ed25519_key_path_for(db_path: str) -> str:
    """Ed25519 私钥路径：与 HMAC 密钥同一策略（用户配置目录，与库分离）。"""
    digest = hashlib.sha256(db_path.encode("utf-8")).hexdigest()[:12]
    basename = os.path.basename(db_path) or "evidence"
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "agenttrace", "keys", f"{basename}.{digest}.ed25519.secret")


def ensure_ed25519_keypair(db_path: str, secret_path: Optional[str] = None) -> "ed25519.Ed25519KeyPair":
    """获取/生成 Ed25519 密钥对。私钥默认存用户配置目录（与库分离）。"""
    if secret_path is None:
        secret_path = os.environ.get("AGENTTRACE_ED25519_SECRET_PATH") or ed25519_key_path_for(db_path)
    hex_env = os.environ.get("AGENTTRACE_ED25519_SECRET_HEX")
    if hex_env:
        return ed25519.Ed25519KeyPair.from_hex(hex_env)
    if os.path.exists(secret_path):
        return ed25519.Ed25519KeyPair.load(secret_path)
    key_dir = os.path.dirname(secret_path)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)
    kp = ed25519.Ed25519KeyPair.generate()
    kp.save_secret(secret_path)
    # 顺手导出公钥文件（供验证端分发）
    kp.save_public(secret_path + ".pub")
    return kp


def seal_anchor(db_path: str, events: list, meta: Dict[str, Any],
                keypair: "ed25519.Ed25519KeyPair") -> Dict[str, Any]:
    """对当前链状态生成 Ed25519 锚定并原子写盘。"""
    genesis = genesis_hash_of(events)
    tip = tip_hash_of(events)
    seq_max = events[-1]["seq"] if events else -1
    mh = hashlib.sha256(canonical_json(meta)).hexdigest()
    payload = _signed_payload(genesis, seq_max, tip, mh)
    record = {
        VERSION_FIELD: VERSION,
        ALGO_FIELD: ALGO,
        PK_FIELD: keypair.public_hex(),
        GENESIS_FIELD: genesis,
        SEQ_FIELD: seq_max,
        TIP_FIELD: tip,
        META_FIELD: mh,
        TS_FIELD: time.time(),
    }
    record[SIG_FIELD] = ed25519.sign(keypair.secret, payload).hex()
    path = db_path + ".anchor.json"
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False)
    os.replace(tmp, path)
    return record


def verify_ed25519_anchor(db_path: str, events: list, meta: Dict[str, Any],
                          expected_public: Optional[str] = None) -> tuple[bool, list[str]]:
    """验证 Ed25519 锚定。

    expected_public: 可选——验证端可传入期望的公钥（来自可信渠道），
    锚定文件内嵌公钥与其不符 = 整库伪造信号。
    返回 (有效, 问题列表)。
    """
    problems: list[str] = []
    path = db_path + ".anchor.json"
    if not os.path.exists(path):
        return False, ["锚定文件不存在（证据库从未锚定）"]
    try:
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return False, [f"锚定文件损坏: {e}"]

    if record.get(VERSION_FIELD) != VERSION:
        return False, [f"锚定版本不支持: {record.get(VERSION_FIELD)}"]
    if record.get(ALGO_FIELD) != ALGO:
        return False, [f"锚定算法不符: {record.get(ALGO_FIELD)}"]

    sig_hex = record.get(SIG_FIELD)
    pub_hex = record.get(PK_FIELD)
    if not sig_hex or not pub_hex:
        return False, ["锚定记录缺少签名或公钥"]
    if expected_public and pub_hex.lower() != expected_public.lower():
        problems.append("锚定公钥与期望公钥不符（整库伪造信号）")

    sig = bytes.fromhex(sig_hex)
    pub = bytes.fromhex(pub_hex)
    # 用锚定内的字段重建 payload（签名只覆盖四元组，不含 ts/版本/算法）
    payload = _signed_payload(record.get(GENESIS_FIELD), record.get(SEQ_FIELD, -1),
                              record.get(TIP_FIELD), record.get(META_FIELD, ""))
    if not ed25519.verify(pub, payload, sig):
        return False, ["锚定签名校验失败（锚定记录被篡改，或公钥不匹配）"]

    # 逐项比对
    cur_genesis = genesis_hash_of(events)
    if cur_genesis != record.get(GENESIS_FIELD):
        problems.append(f"genesis 哈希不匹配（整条链被替换）")
    cur_seq_max = events[-1]["seq"] if events else -1
    if cur_seq_max != record.get(SEQ_FIELD):
        problems.append(f"链尾 seq 不匹配（末尾截断或被追加伪造）: 库 {cur_seq_max} vs 锚定 {record.get(SEQ_FIELD)}")
    cur_tip = tip_hash_of(events)
    if cur_tip != record.get(TIP_FIELD):
        problems.append("链尾哈希不匹配（事件内容被改写）")
    cur_mh = hashlib.sha256(canonical_json(meta)).hexdigest()
    if cur_mh != record.get(META_FIELD):
        problems.append("meta 哈希不匹配（会话元信息被篡改）")

    return not problems, problems


def anchor_state_v2(db_path: str) -> Dict[str, Any]:
    """v2 锚定状态探测（验证端视角：无需私钥）。"""
    path = db_path + ".anchor.json"
    has_anchor = os.path.exists(path)
    secret_path = os.environ.get("AGENTTRACE_ED25519_SECRET_PATH") or ed25519_key_path_for(db_path)
    has_secret = bool(os.environ.get("AGENTTRACE_ED25519_SECRET_HEX")) or os.path.exists(secret_path)
    return {
        "has_anchor_file": has_anchor,
        "has_secret": has_secret,
        "algo": "ed25519",
    }