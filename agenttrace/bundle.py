"""AgentTrace 证据包导出（v0.5.0）：把一次审计的全部证据打成一个可独立验证的 zip。

证据包内容（bundle）：
    manifest.json          — 包清单：文件名 → SHA-256，+ 打包时间/版本/链状态
    evidence.db            — 证据库本体（哈希链 + 全部事件）
    evidence.db.anchor.json — 外部锚定（HMAC 或 Ed25519）
    anchor.public_key.txt  — Ed25519 公钥（若有；验证者用它绑定验证）
    report.html            — 时间线回放审计报告
    README.txt             — 验证者指引（如何独立验证这个包）

设计原则：
  - manifest 覆盖所有文件哈希 → 包内任何文件被替换都能发现
  - 解包后标准 verify/seal verify 流程照常工作（不做私有格式）
  - 验证者只需要 AgentTrace 本身 + 包，不需要签名私钥
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import zipfile
from typing import Any, Dict, List, Optional

from . import __version__
from .analyzer import analyze_chain
from .report import render_report_file
from .store import EvidenceStore

MANIFEST = "manifest.json"
README_NAME = "README.txt"


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_bundle_files(db_path: str, report_path: Optional[str] = None) -> List[str]:
    """收集应入包的文件（存在者才入）。"""
    files = [db_path]
    anchor = db_path + ".anchor.json"
    if os.path.exists(anchor):
        files.append(anchor)
    if report_path and os.path.exists(report_path):
        files.append(report_path)
    return files


VERIFIER_README = """AgentTrace 证据包（Evidence Bundle）
=====================================

本包由 AgentTrace v{version} 于 {created} 打包。

包内容
------
  evidence.db             证据库（SQLite；SHA-256 哈希链 + 全部 Agent 事件）
  evidence.db.anchor.json 外部锚定签名（对链尾四元组的签名承诺）
  anchor.public_key.txt   Ed25519 公钥（若有——验证时用它绑定）
  report.html             时间线回放审计报告
  manifest.json           包清单（每个文件的 SHA-256）

验证步骤（验证者需要：AgentTrace + 本包；不需要签名私钥）
--------------------------------------------------------
1. 校验包清单（任何文件被替换都会在此暴露）:
     python -m agenttrace bundle verify-manifest <解包目录>

2. 校验证据链 + 外部锚定:
     python -m agenttrace verify --db <解包目录>/evidence.db
     # Ed25519 锚定请加绑定期望公钥（对抗/合规场景必须）:
     python -m agenttrace seal verify --db <解包目录>/evidence.db \\
         --public-key <从可信渠道获得的公钥，应与 anchor.public_key.txt 一致>

3. 打开 report.html 查看时间线回放与风险发现。

安全须知
--------
- 本包验证的是"包内数据自洽 + 与锚定一致"。
- 公钥的信任来自分发渠道（band 之外），请通过独立渠道核对 anchor.public_key.txt。
- 若 anchor 缺失或密钥/公钥不匹配，证据链完整性无法证明，请勿采信。
"""


def export_bundle(
    db_path: str,
    out_path: str,
    title: str = "AgentTrace 审计报告",
    redact: bool = False,
) -> str:
    """导出证据包 zip。返回包路径。

    流程：生成最新报告 → 收集文件 → 写 manifest（各文件 SHA-256）→ 打 zip。
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"证据库不存在: {db_path}")

    # 1. 生成最新报告（临时文件，随包带走，打包时统一命名为 report.html）
    tmp_report = os.path.join(
        tempfile.gettempdir(),
        f"agenttrace_report_{os.getpid()}_{int(time.time() * 1000)}.html",
    )
    store = EvidenceStore(db_path)
    events = store.all_events()
    meta = store.all_meta()
    store.close()
    if not events:
        raise ValueError("证据库为空，无法导出证据包")
    findings = analyze_chain(events)
    anchored = os.path.exists(db_path + ".anchor.json")
    render_report_file(events, findings, meta, tmp_report, title=title,
                       anchored=anchored if anchored else None, redact=redact)

    try:
        bundle_files = _collect_bundle_files(db_path, tmp_report)
        # 规范名映射：无论源库名是什么，包内统一为 evidence.db（与 README 指引一致，
        # 防止验证者按文档路径误指到不存在的文件、被 sqlite 静默建空库误导）
        base = os.path.basename(db_path)
        name_map = {
            tmp_report: "report.html",
            db_path: "evidence.db",
        }
        if base != "evidence.db":
            name_map[db_path + ".anchor.json"] = "evidence.db.anchor.json"

        # 2. manifest：文件名 → sha256
        created = time.strftime("%Y-%m-%d %H:%M:%S")
        manifest: Dict[str, Any] = {
            "bundle_version": 1,
            "agenttrace_version": __version__,
            "created_at": created,
            "files": {},
        }
        for f in bundle_files:
            name = name_map.get(f, os.path.basename(f))
            manifest["files"][name] = {
                "sha256": _sha256_file(f),
                "size": os.path.getsize(f),
            }
        # Ed25519 锚定：从锚定记录内嵌公钥生成 anchor.public_key.txt（验证者绑定用）
        anchor_src = db_path + ".anchor.json"
        if anchored and os.path.exists(anchor_src):
            with open(anchor_src, encoding="utf-8") as f:
                anchor_data = json.load(f)
            if anchor_data.get("public_key"):
                manifest["files"]["anchor.public_key.txt"] = {
                    "sha256": hashlib.sha256(
                        (anchor_data["public_key"] + "\n").encode("utf-8")).hexdigest(),
                    "size": len(anchor_data["public_key"]) + 1,
                }

        # 3. 打包（zip 内固定顶层目录名，避免解包散落）
        top = os.path.splitext(os.path.basename(out_path))[0] or "agenttrace-bundle"
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in bundle_files:
                zf.write(f, arcname=f"{top}/{name_map.get(f, os.path.basename(f))}")
            # Ed25519 公钥（内容已在 manifest 登记）
            anchor_src = db_path + ".anchor.json"
            if anchored and os.path.exists(anchor_src):
                with open(anchor_src, encoding="utf-8") as f:
                    anchor_data = json.load(f)
                if anchor_data.get("public_key"):
                    zf.writestr(f"{top}/anchor.public_key.txt",
                                anchor_data["public_key"] + "\n")
            zf.writestr(f"{top}/{MANIFEST}", json.dumps(manifest, ensure_ascii=False, indent=2))
            zf.writestr(f"{top}/{README_NAME}",
                        VERIFIER_README.format(version=__version__, created=created))
        return out_path
    finally:
        if os.path.exists(tmp_report):
            os.remove(tmp_report)


def verify_manifest(bundle_dir: str) -> tuple[bool, List[str]]:
    """校验解包后的 bundle 目录：manifest 中每个文件的哈希。

    返回 (有效, 问题列表)。manifest 自身不签名——它防的是"包内单文件
    被悄悄替换"；整包伪造的防线在 anchor + 公钥绑定（README 已说明）。
    """
    problems: List[str] = []
    mpath = os.path.join(bundle_dir, MANIFEST)
    if not os.path.exists(mpath):
        return False, [f"manifest 不存在: {mpath}"]
    try:
        with open(mpath, encoding="utf-8") as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return False, [f"manifest 损坏: {e}"]

    files = manifest.get("files", {})
    if not files:
        return False, ["manifest 无文件记录"]

    # 逐文件校验
    for name, info in files.items():
        fpath = os.path.join(bundle_dir, name)
        if not os.path.exists(fpath):
            problems.append(f"文件缺失: {name}")
            continue
        actual = _sha256_file(fpath)
        if actual != info.get("sha256"):
            problems.append(f"哈希不匹配（文件被替换）: {name}")

    # 反向检查：目录里有 manifest 未记录的文件（新增文件提示）
    known = set(files) | {MANIFEST, README_NAME}
    for name in os.listdir(bundle_dir):
        if os.path.isfile(os.path.join(bundle_dir, name)) and name not in known:
            problems.append(f"未在 manifest 中的新增文件: {name}")

    return not problems, problems