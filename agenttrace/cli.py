"""AgentTrace 命令行入口。

用法:
    python -m agenttrace record <session.jsonl> [--db evidence.db]
    python -m agenttrace record --stdin [--db evidence.db]
    python -m agenttrace verify [--db evidence.db]
    python -m agenttrace analyze [--db evidence.db] [--json]
    python -m agenttrace report [--db evidence.db] [--out report.html] [--title "审计报告"]
    python -m agenttrace init [--db evidence.db] [--agent hermes] [--model ...]

    * --db 默认 evidence.db（当前目录）
    * 未指定子命令时显示帮助
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional

from . import __version__
from .anchor import (
    Anchor, anchor_path_for, anchor_state, ensure_key,
    key_path_for, legacy_key_path_for, load_key_for,
)
from .analyzer import analyze_chain, summarize
from .recorder import Recorder, make_session_start, make_session_end
from .report import render_report_file
from .store import EvidenceStore


def _default_db() -> str:
    return os.environ.get("AGENTTRACE_DB", "evidence.db")


def cmd_init(args: argparse.Namespace) -> int:
    anchor_key = None
    if args.anchor:
        anchor_key = ensure_key(args.db, args.anchor_key_path)
        state = anchor_state(args.db)
        loc = state["key_location"]
        loc_note = {
            "env": "环境变量注入",
            "explicit": f"显式路径 ({args.anchor_key_path})",
            "config-dir": f"用户配置目录 ({key_path_for(args.db)})",
            "legacy": f"旧位置（与库同目录，建议迁移）: {legacy_key_path_for(args.db)}",
        }.get(loc, loc)
        print(f"🔑 锚定密钥: {anchor_key.hex()[:8]}… (位置: {loc_note})")
    store = EvidenceStore(args.db, anchor_key=anchor_key)
    store.set_meta("agent", args.agent)
    if args.model:
        store.set_meta("model", args.model)
    if args.tools:
        try:
            tools = json.loads(args.tools)
        except json.JSONDecodeError:
            tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    else:
        tools = []
    store.set_meta("tools", tools)
    store.set_meta("created_at", time.time())
    # 写入 session_start 作为链首
    rec = Recorder(store)
    rec.ingest(make_session_start(agent=args.agent, model=args.model, tools=tools))
    if anchor_key is not None:
        print(f"✔ 初始化已锚定证据库: {args.db} (链首已写入, 共 {store.count()} 条, 锚定 {anchor_path_for(args.db)})")
    else:
        print(f"✔ 初始化证据库: {args.db} (链首已写入, 共 {store.count()} 条)")
        print("⚠ 未锚定: 建议加 --anchor 启用外部签名（否则防不了整链重写/末尾截断）")
    store.close()
    return 0


def _print_verify(store: EvidenceStore, db_path: str) -> int:
    """verify 分级输出：
      0 = 完整有效 + 锚定验证通过
      1 = 链自洽但未锚定（锚定文件不存在），仅警告
      2 = 链异常 或 确认的 HMAC 锚定损坏/密钥被销毁（疑似人为破坏）
    """
    events = store.all_events()
    ok, problems, total = store.verify()
    anchored = store.anchor is not None
    # 分离"未锚定"警告与真实异常
    real = [p for p in problems if not p.startswith("未锚定")]

    # 复评 v1.0 P1：锚定体系分派——同一文件路径下先判 version/algo
    state = anchor_state(db_path)
    anchor_kind = None
    if state["has_anchor_file"]:
        try:
            with open(anchor_path_for(db_path), encoding="utf-8") as f:
                rec = json.load(f)
            anchor_kind = rec.get("algo") or (f"v{rec.get('version', 1)}")
        except (json.JSONDecodeError, OSError):
            anchor_kind = "broken"

    if anchor_kind == "ed25519":
        # v2 Ed25519 锚定：verify 走 seal verify 语义，绝不判"人为破坏"。
        # 注意：此时不能用 store.verify()（它按 v1/HMAC 逻辑校验会误报"缺 mac"），
        # 只做纯哈希链校验（Ed25519 签名校验交给 seal verify）。
        from .chain import verify_chain as _vc
        chain_ok, chain_problems = _vc(events)
        if chain_ok:
            print(f"✔ 证据链完整有效: {total} 条事件，全部哈希验证通过")
            print(f"   🔐 Ed25519 外部锚定（公钥验证请用: "
                  f"agenttrace seal verify --db {db_path} --public-key <hex>）")
            store.close()
            return 0
        print(f"✘ 证据链异常: {len(chain_problems)} 处问题")
        for p in chain_problems:
            print(f"   - {p}")
        store.close()
        return 2

    # 4.2/复评 P1：只有确认是 v1 HMAC 体系时才报"疑似人为破坏"
    if state["has_anchor_file"] and not state["key_available"] and anchor_kind in (None, "v1", "broken"):
        print(f"✘ 严重: 锚定文件存在（{anchor_path_for(db_path)}）但签名密钥缺失")
        print(f"   疑似人为破坏——证据链完整性已无法验证，请立即恢复密钥或对现场做镜像")
        store.close()
        return 2

    if ok:
        print(f"✔ 证据链完整有效: {total} 条事件，全部哈希验证通过")
        if anchored:
            if state["key_location"] == "legacy":
                print(f"   🔐 外部锚定有效（⚠ 密钥仍在库目录旧位置，建议迁移到用户配置目录: "
                      f"{key_path_for(db_path)}）")
            elif state["key_location"] == "env":
                print("   🔐 外部锚定有效（密钥: 环境变量注入）")
            elif state["key_location"] == "explicit":
                print("   🔐 外部锚定有效（密钥: 显式路径）")
            else:
                print(f"   🔐 外部锚定有效（genesis/tip/meta 均与签名一致，密钥: 用户配置目录）")
        else:
            print(f"   ⚠ 未锚定: 只能防内部不一致，防不了整链重写/末尾截断/元信息篡改")
            print(f"     建议: agenttrace init --anchor 或重建库时启用锚定")
        store.close()
        return 0 if anchored else 1
    if not real:
        print(f"⚠ 证据链自洽 ({total} 条) 但未锚定，无法证明未被整体替换")
        store.close()
        return 1
    print(f"✘ 证据链异常: {total} 条事件，{len(real)} 处问题")
    for p in real:
        print(f"   - {p}")
    store.close()
    return 2


def cmd_verify(args: argparse.Namespace) -> int:
    # 终评 4.1：密钥解析与 anchor_state 同一优先级（ENV HEX/PATH → 配置目录 → 旧位置）
    anchor_key = load_key_for(args.db)
    store = EvidenceStore(args.db, anchor_key=anchor_key)
    return _print_verify(store, args.db)


def cmd_record(args: argparse.Namespace) -> int:
    # record 时加载锚定密钥以继续更新锚定（同一优先级解析，终评 4.1）
    anchor_key = load_key_for(args.db)
    store = EvidenceStore(args.db, anchor_key=anchor_key)
    rec = Recorder(store)
    before = store.count()
    if args.stdin:
        n = rec.ingest_stdin()
        print(f"✔ 从 stdin 摄入 {n} 条事件 → {args.db} (共 {before + n} 条)")
    else:
        n = rec.ingest_jsonl_file(args.file)
        print(f"✔ 从 {args.file} 摄入 {n} 条事件 → {args.db} (共 {before + n} 条)")
    if anchor_key is not None:
        ok, problems, total = store.verify()
        if ok:
            print(f"✔ 证据链验证通过 ({total} 条, 锚定已更新)")
        else:
            print(f"✘ 证据链验证失败 ({len(problems)} 处问题):")
            for p in problems[:10]:
                print(f"   - {p}")
            store.close()
            return 2
    else:
        # 未锚定：只做内部一致性校验
        events = store.all_events()
        from .chain import verify_chain as _vc
        ok, problems = _vc(events)
        if ok:
            print(f"✔ 证据链自洽 ({len(events)} 条) ⚠ 未锚定（无法防整链重写/末尾截断）")
        else:
            print(f"✘ 证据链异常 ({len(problems)} 处):")
            for p in problems[:10]:
                print(f"   - {p}")
            store.close()
            return 2
    store.close()
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    store = EvidenceStore(args.db)
    events = store.all_events()
    findings = analyze_chain(events)
    summ = summarize(findings)
    if args.json:
        print(json.dumps({
            "events": len(events),
            "summary": summ,
            "findings": [f.to_dict() for f in findings],
        }, ensure_ascii=False, indent=2))
    else:
        print(f"事件: {len(events)} | 发现: {summ['total']} "
              f"(高 {summ['by_severity'].get('high', 0)} / "
              f"中 {summ['by_severity'].get('medium', 0)} / "
              f"低 {summ['by_severity'].get('low', 0)})")
        for f in findings:
            print(f"  [{f.severity.upper():6}] #{f.seq:4d} {f.category} - {f.title}")
            print(f"           {f.detail[:100]}")
    store.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    anchor_key = load_key_for(args.db)
    store = EvidenceStore(args.db, anchor_key=anchor_key)
    events = store.all_events()
    findings = analyze_chain(events)
    meta = store.all_meta()
    if not events:
        print("✘ 证据库为空，无法生成报告", file=sys.stderr)
        store.close()
        return 1
    anchored = store.anchor is not None
    anchor_info = ""
    if anchored:
        aok, aproblems = store.anchor.verify(events, store.all_meta())
        anchor_info = "锚定有效" if aok else ("锚定异常: " + "; ".join(aproblems[:2]))
    elif os.path.exists(args.db + ".anchor.json"):
        # Ed25519 锚定（seal 后无 HMAC key）——同样视为已锚定，徽章显示
        anchored = True
        anchor_info = "Ed25519 外部锚定（公钥验证见 seal verify）"
    out = render_report_file(events, findings, meta, args.out, title=args.title,
                             anchored=anchored, anchor_info=anchor_info,
                             redact=args.redact)
    print(f"✔ 报告已生成: {out}")
    store.close()
    return 0


def cmd_aggregate(args: argparse.Namespace) -> int:
    """跨库聚合审计（v0.7）：多会话画像 + 风险排行。"""
    from .aggregate import aggregate_dbs, render_agg_html, render_agg_text
    dbs = [p.strip() for p in args.dbs.split(",") if p.strip()]
    if not dbs:
        print("✘ 未指定证据库（--dbs a.db,b.db）", file=sys.stderr)
        return 1
    agg = aggregate_dbs(dbs, title=args.title)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(render_agg_html(agg))
        print(f"✔ 聚合报告已生成: {args.out}")
    print(render_agg_text(agg))
    return 0


def cmd_tsa(args: argparse.Namespace) -> int:
    """RFC3161 时间戳锚定（v0.9）。"""
    from .tsa import stamp, verify
    if args.action == "stamp":
        try:
            res = stamp(args.db, args.tsa_url, timeout=args.timeout)
        except (FileNotFoundError, RuntimeError, ValueError) as e:
            print(f"✘ 时间戳失败: {e}", file=sys.stderr)
            return 1
        print(f"✔ 时间戳已授予: {res.get('status_name', '?')} "
              f"@ {res.get('gen_time', '?')}")
        print(f"   绑定锚定哈希: {res.get('anchor_sha256', '?')[:16]}…")
        print(f"   TSR: {args.db}.anchor.tsr  (外部验签: "
              f"openssl ts -verify -data {args.db}.anchor.tsq -in {args.db}.anchor.tsr -CAfile <tsa_cert.pem>)")
        return 0
    if args.action == "verify":
        ok, problems = verify(args.db)
        if ok:
            print("✔ 时间戳绑定有效: messageImprint 与当前锚定哈希一致")
            if args.cafile:
                # v1.1：零依赖 CMS 验签（真实密码学验证 + 信任锚定）
                from .cms import load_ca_pem, verify_cms
                tsr_p = args.db + ".anchor.tsr"
                try:
                    ca_certs = load_ca_pem(args.cafile)
                except (OSError, ValueError) as e:
                    print(f"✘ CA 文件读取失败: {e}", file=sys.stderr)
                    return 2
                with open(tsr_p, "rb") as f:
                    tsr_bytes = f.read()
                res = verify_cms(tsr_bytes, ca_certs=ca_certs)
                if res["verified"]:
                    print(f"✔ CMS 签名验证通过（level={res['level']}，"
                          f"genTime={res.get('gen_time')}）")
                    print("   时间戳来自 --cafile 受信 CA 链，可用于法律级证明")
                    return 0
                print(f"✘ CMS 签名验证失败: "
                      f"{'; '.join(res['problems']) or '证书链未通过信任锚定'}")
                return 2
            print("⚠ 未验证 TSA 的 CMS 签名——本校验不能证明时间戳来自真实 TSA")
            print(f"   加 --cafile <tsa_ca.pem> 可做零依赖 CMS 验签；或:")
            print(f"   openssl ts -verify -data {args.db}.anchor.tsq "
                  f"-in {args.db}.anchor.tsr -CAfile <tsa_cert.pem>")
            return 0
        print(f"✘ 时间戳验证失败: {len(problems)} 处问题")
        for p in problems:
            print(f"   - {p}")
        return 2
    print(f"✘ 未知 tsa 子命令: {args.action}", file=sys.stderr)
    return 1


def cmd_seal(args: argparse.Namespace) -> int:
    """Ed25519 锚定（v0.4）：私钥只在签名端，公钥可分发给任何验证者。"""
    from .anchor_v2 import (
        ensure_ed25519_keypair, seal_anchor, verify_ed25519_anchor, anchor_state_v2,
    )
    if args.action == "keygen":
        kp = ensure_ed25519_keypair(args.db, args.secret_path)
        print(f"🔑 Ed25519 私钥已生成/加载（签名端保管，勿外传）")
        print(f"   公钥: {kp.public_hex()}")
        print(f"   公钥可自由分发给验证端；私钥泄露 = 可伪造锚定")
        return 0

    store = EvidenceStore(args.db)
    events = store.all_events()
    meta = store.all_meta()
    if not events:
        print("✘ 证据库为空，无法锚定", file=sys.stderr)
        store.close()
        return 1

    if args.action == "seal":
        kp = ensure_ed25519_keypair(args.db, args.secret_path)
        rec = seal_anchor(args.db, events, meta, kp)
        print(f"🔒 Ed25519 锚定已写入: {args.db}.anchor.json")
        print(f"   seq_max={rec['seq_max']}  公钥={rec['public_key'][:16]}…")
        print(f"   私钥位置: 用户配置目录（与库分离）；公钥可分发验证")
        ok, problems = verify_ed25519_anchor(args.db, events, meta)
        if ok:
            print("✔ 锚定自验通过")
            store.close()
            return 0
        print("✘ 锚定自验失败:", problems)
        store.close()
        return 2

    if args.action == "verify":
        st = anchor_state_v2(args.db)
        expected = None
        if args.public_key:
            expected = args.public_key.strip()
        if expected is None:
            # 复评 P1：默认路径无信任根——必须显式降级警告（与未锚定警告对齐）
            print("⚠ 未绑定期望公钥: 本验证只能证明锚定自洽，无法排除\"攻击者自造密钥重签\"")
            print("   对抗/合规场景请用 --public-key <hex> 绑定可信渠道分发的公钥")
        ok, problems = verify_ed25519_anchor(args.db, events, meta, expected_public=expected)
        if ok:
            if expected is not None:
                print(f"✔ Ed25519 锚定验证通过: {len(events)} 条事件（公钥已绑定，伪造可检出）")
            else:
                print(f"✔ Ed25519 锚定自洽: {len(events)} 条事件（⚠ 仅自洽校验，非防伪造证明）")
            store.close()
            return 0
        if st["has_anchor_file"] and not st["has_secret"] and not any("签名" in p for p in problems):
            print("✘ 严重: 锚定文件存在但签名私钥缺失（签名端）——疑似人为破坏")
        else:
            print("✘ Ed25519 锚定验证失败:")
            for p in problems:
                print(f"   - {p}")
        store.close()
        return 2
    print(f"✘ 未知 seal 子命令: {args.action}", file=sys.stderr)
    store.close()
    return 1


def cmd_bundle(args: argparse.Namespace) -> int:
    """证据包导出与包清单校验（v0.5）。"""
    from .bundle import export_bundle, verify_manifest
    if args.action == "export":
        out_path = args.out or (os.path.splitext(args.db)[0] + "-bundle.zip")
        try:
            out = export_bundle(args.db, out_path, title=args.title, redact=args.redact)
        except (FileNotFoundError, ValueError) as e:
            print(f"✘ 导出失败: {e}", file=sys.stderr)
            return 1
        size = os.path.getsize(out)
        # 复评 v1.0 P2：未锚定库导出必须显式告警（降级绝不静默）
        anchor_path = args.db + ".anchor.json"
        if not os.path.exists(anchor_path):
            print("⚠ 未锚定证据库: 包内证据链只能自洽校验，无法对抗整链重写/末尾截断")
            print(f"   建议: agenttrace init --anchor 重建，或 seal seal 后重新导出")
        print(f"📦 证据包已导出: {out} ({size:,} bytes)")
        print(f"   解包后: python -m agenttrace bundle verify-manifest <目录>")
        print(f"           python -m agenttrace verify --db <目录>/evidence.db")
        return 0
    if args.action == "verify-manifest":
        target = args.bundle_dir or "."
        ok, problems = verify_manifest(target)
        if ok:
            print(f"✔ 包清单校验通过: 所有文件哈希一致（{target}）")
            return 0
        print(f"✘ 包清单校验失败: {len(problems)} 处问题")
        for p in problems:
            print(f"   - {p}")
        return 2
    print(f"✘ 未知 bundle 子命令: {args.action}", file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agenttrace",
        description="AI Agent 取证审计工具 — 防篡改证据链 + 风险分析 + 时间线回放报告",
    )
    parser.add_argument("--version", action="version", version=f"agenttrace {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init", help="初始化证据库（写入 session_start 链首）")
    p_init.add_argument("--db", default=_default_db(), help="证据库路径 (默认 evidence.db)")
    p_init.add_argument("--agent", default="unknown", help="Agent 名称 (如 hermes/codex)")
    p_init.add_argument("--model", default="", help="模型名称")
    p_init.add_argument("--tools", default="", help="工具清单 (JSON 或逗号分隔)")
    p_init.add_argument("--anchor", action="store_true",
                        help="启用外部锚定：生成 HMAC-SHA256 签名密钥（防整链重写/末尾截断/元信息篡改）")
    p_init.add_argument("--anchor-key-path", default=None,
                        help="锚定密钥路径（默认 <db>.anchor.key；也可用环境变量 AGENTTRACE_ANCHOR_KEY_HEX/PATH）")

    p_rec = sub.add_parser("record", help="摄入事件（JSONL 文件或 stdin 流）")
    p_rec.add_argument("file", nargs="?", help="JSONL 文件路径；缺省结合 --stdin")
    p_rec.add_argument("--stdin", action="store_true", help="从 stdin 实时读取")
    p_rec.add_argument("--db", default=_default_db(), help="证据库路径")

    p_ver = sub.add_parser("verify", help="验证证据链完整性（含外部锚定，若已锚定）")
    p_ver.add_argument("--db", default=_default_db(), help="证据库路径")

    p_ana = sub.add_parser("analyze", help="风险分析")
    p_ana.add_argument("--db", default=_default_db(), help="证据库路径")
    p_ana.add_argument("--json", action="store_true", help="JSON 输出")

    p_rep = sub.add_parser("report", help="生成 HTML 时间线回放报告")
    p_rep.add_argument("--db", default=_default_db(), help="证据库路径")
    p_rep.add_argument("--out", default="report.html", help="输出 HTML 路径")
    p_rep.add_argument("--title", default="AgentTrace 审计报告", help="报告标题")
    p_rep.add_argument("--redact", action="store_true",
                       help="脱敏：报告中的密钥/PII 打码（证据库本体不变）")

    p_agg = sub.add_parser("aggregate", help="跨库聚合审计（v0.7）：多会话画像")
    p_agg.add_argument("--dbs", required=True,
                       help="逗号分隔的证据库列表（如 a.db,b.db,c.db）")
    p_agg.add_argument("--out", default=None, help="输出 HTML 聚合报告路径（可选）")
    p_agg.add_argument("--title", default="AgentTrace 聚合审计", help="报告标题")

    p_tsa = sub.add_parser("tsa", help="RFC3161 时间戳锚定（v0.9）：stamp/verify")
    p_tsa.add_argument("action", choices=["stamp", "verify"],
                       help="stamp=向 TSA 打时间戳, verify=校验哈希绑定")
    p_tsa.add_argument("--db", default=_default_db(), help="证据库路径")
    p_tsa.add_argument("--tsa-url", default="https://freetsa.org/tsr",
                       help="TSA 服务 URL（默认公共 freetsa.org）")
    p_tsa.add_argument("--timeout", type=float, default=15.0, help="HTTP 超时秒数")
    p_tsa.add_argument("--cafile", default=None,
                       help="verify 时做 CMS 验签的受信 CA（PEM bundle 路径）")

    p_seal = sub.add_parser("seal", help="Ed25519 外部锚定（v0.4）：keygen/seal/verify")
    p_seal.add_argument("action", choices=["keygen", "seal", "verify"],
                        help="keygen=生成密钥对, seal=签名当前链状态, verify=公钥验证")
    p_seal.add_argument("--db", default=_default_db(), help="证据库路径")
    p_seal.add_argument("--secret-path", default=None,
                        help="Ed25519 私钥路径（默认用户配置目录；也可 AGENTTRACE_ED25519_SECRET_HEX/PATH）")
    p_seal.add_argument("--public-key", default=None,
                        help="verify 时期望的公钥（hex，来自可信渠道；不符 = 整库伪造信号）")

    p_bundle = sub.add_parser("bundle", help="证据包（v0.5）：export/verify-manifest")
    p_bundle.add_argument("action", choices=["export", "verify-manifest"],
                          help="export=导出证据包 zip, verify-manifest=校验解包目录")
    p_bundle.add_argument("bundle_dir", nargs="?", default=None,
                          help="verify-manifest 的解包目录（顶层含 manifest.json）")
    p_bundle.add_argument("--db", default=_default_db(), help="证据库路径（export 用）")
    p_bundle.add_argument("--out", default=None, help="导出 zip 路径（默认 evidence-bundle.zip）")
    p_bundle.add_argument("--title", default="AgentTrace 审计报告", help="包内报告标题")
    p_bundle.add_argument("--redact", action="store_true",
                          help="包内报告脱敏（证据库/锚定本体不变）")

    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 1

    return {
        "init": cmd_init,
        "record": cmd_record,
        "verify": cmd_verify,
        "analyze": cmd_analyze,
        "report": cmd_report,
        "aggregate": cmd_aggregate,
        "tsa": cmd_tsa,
        "seal": cmd_seal,
        "bundle": cmd_bundle,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())