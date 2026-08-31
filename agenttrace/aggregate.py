"""AgentTrace 多会话聚合（v0.7.0）：跨证据库审计画像。

取证场景天然单元是"一个库 = 一次会话/一个事故"（events 链内 seq 连续、
meta 记录 agent/model）。聚合器扫描多个库，产出：

    per-db profile：事件数 / 类型分布 / agent / model / 时间跨度 /
                    风险发现（按类别与严重度分布）/ 链验证状态
    全局画像：总事件 / 总风险 / 风险类别排行 / 高危事件 Top

输出：结构化 dict（可被 report 渲染成 HTML）。
"""

from __future__ import annotations

import datetime
import os
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from .analyzer import CATEGORY_NAMES, analyze_chain
from .chain import verify_chain
from .store import EvidenceStore

SEV_ORDER = {"high": 3, "medium": 2, "low": 1}


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        return f"{ts:.3f}"


def profile_db(db_path: str) -> Dict[str, Any]:
    """单库画像。返回结构化 dict；库不存在/为空时返回带 error 的 profile。"""
    prof: Dict[str, Any] = {"db": os.path.basename(db_path), "path": db_path, "error": None}
    if not os.path.exists(db_path):
        prof["error"] = "文件不存在"
        return prof
    store = EvidenceStore(db_path)
    events = store.all_events()
    meta = store.all_meta()
    chain_ok, chain_problems = verify_chain(events)
    found_anchor = os.path.exists(db_path + ".anchor.json")
    store.close()

    prof.update(
        event_count=len(events),
        meta=meta,
        chain_ok=chain_ok,
        chain_problems=chain_problems,
        anchored=found_anchor,
    )
    if not events:
        prof["error"] = "证据库为空"
        return prof

    # 时间跨度
    ts = [e.get("ts", 0) for e in events]
    prof["t_start"] = min(ts)
    prof["t_end"] = max(ts)
    prof["duration_s"] = max(ts) - min(ts)

    # 类型分布
    prof["type_dist"] = dict(Counter(e.get("type", "?") for e in events))

    # 风险画像
    findings = analyze_chain(events)
    prof["findings"] = findings
    prof["finding_count"] = len(findings)
    prof["sev_dist"] = dict(Counter(f.severity for f in findings))
    cat_count = Counter(f.category for f in findings)
    prof["cat_dist"] = {c: cat_count[c] for c in sorted(cat_count, key=lambda c: -cat_count[c])}
    # TOP 高危（按严重度排序取 5）
    top = sorted(findings, key=lambda f: (SEV_ORDER.get(f.severity, 0), f.seq), reverse=True)[:5]
    prof["top_findings"] = [f.to_dict() for f in top]
    return prof


def aggregate_dbs(db_paths: List[str], title: str = "AgentTrace 聚合审计") -> Dict[str, Any]:
    """跨库聚合。返回聚合画像 dict（含 profiles + 全局统计 + 风险排行）。"""
    profiles = [profile_db(p) for p in db_paths]
    total_events = sum(p.get("event_count", 0) for p in profiles)
    total_findings = sum(p.get("finding_count", 0) for p in profiles)
    all_sev = Counter()
    all_cat = Counter()
    agents = Counter()
    for p in profiles:
        all_sev.update(p.get("sev_dist", {}))
        all_cat.update(p.get("cat_dist", {}))
        m = p.get("meta") or {}
        if m.get("agent"):
            agents[m["agent"]] += 1
    cat_rank = [{"category": c, "count": all_cat[c],
                 "category_name": CATEGORY_NAMES.get(c, c)}
                for c in sorted(all_cat, key=lambda c: -all_cat[c])]
    warn_dbs = [p for p in profiles if not p.get("chain_ok", True)]
    return {
        "title": title,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "db_count": len(profiles),
        "profiles": profiles,
        "total_events": total_events,
        "total_findings": total_findings,
        "sev_dist": dict(all_sev),
        "cat_rank": cat_rank,
        "agents": dict(agents),
        "warn_dbs": [p["db"] for p in warn_dbs],
        "error_dbs": [p["db"] for p in profiles if p.get("error")],
    }


# ---------------------------------------------------------------------------
# HTML 渲染（复用报告暗色视觉语言）
# ---------------------------------------------------------------------------

def render_agg_html(agg: Dict[str, Any]) -> str:
    esc = lambda v: str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")  # noqa: E731
    rows = []
    for p in agg["profiles"]:
        if p.get("error"):
            rows.append(
                f'<tr><td>{esc(p["db"])}</td>'
                f'<td colspan="5" class="err">⚠ {esc(p["error"])}</td></tr>'
            )
            continue
        chain_badge = "✅" if p.get("chain_ok") else "⛔ 链异常"
        anchor_badge = "🔐" if p.get("anchored") else "⚠ 未锚定"
        meta = p.get("meta") or {}
        rows.append(
            f'<tr>'
            f'<td>{esc(p["db"])}</td>'
            f'<td>{p.get("event_count", 0)}</td>'
            f'<td>{esc(meta.get("agent", "?"))}<br><small>{esc(meta.get("model", ""))}</small></td>'
            f'<td>{p.get("finding_count", 0)}</td>'
            f'<td><span class="sev-h">{p.get("sev_dist", {}).get("high", 0)}H</span> '
            f'<span class="sev-m">{p.get("sev_dist", {}).get("medium", 0)}M</span> '
            f'<span class="sev-l">{p.get("sev_dist", {}).get("low", 0)}L</span></td>'
            f'<td>{chain_badge} {anchor_badge}</td>'
            f'</tr>'
        )
    profiles_html = "\n".join(rows)

    # 风险类别排行
    cat_rows = "".join(
        f'<tr><td>{esc(r["category_name"])}</td><td>{r["count"]}</td></tr>'
        for r in agg["cat_rank"]
    ) or '<tr><td colspan="2" class="empty">无风险发现</td></tr>'

    # TOP 风险（跨库拼接各库 top2）
    top_rows = []
    for p in agg["profiles"]:
        for f in p.get("top_findings", [])[:2]:
            top_rows.append(
                f'<tr><td>{esc(p["db"])}</td>'
                f'<td><span class="sev-dot sev-{esc(f["severity"])}"></span>{esc(f["severity"].upper())}</td>'
                f'<td>{esc(f["category_name"])}</td>'
                f'<td>{esc(f["title"])}</td>'
                f'<td><code>{esc(f["detail"][:80])}</code></td></tr>'
            )
    top_html = "\n".join(top_rows) or '<tr><td colspan="5" class="empty">无</td></tr>'

    warn_html = ""
    if agg.get("warn_dbs"):
        warn_html = '<div class="warn">⚠ 链异常库: ' + "、".join(esc(w) for w in agg["warn_dbs"]) + "</div>"
    if agg.get("error_dbs"):
        warn_html += '<div class="warn">✘ 无法读取库: ' + "、".join(esc(w) for w in agg["error_dbs"]) + "</div>"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{esc(agg["title"])}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: "Segoe UI", "Microsoft YaHei", sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }}
  h1 {{ color: #f8fafc; font-size: 22px; }}
  .sub {{ color: #94a3b8; font-size: 12px; margin: 6px 0 18px; }}
  .metrics {{ display: flex; gap: 16px; margin: 14px 0 22px; }}
  .metric {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px 22px; }}
  .metric .num {{ font-size: 26px; font-weight: 700; color: #f8fafc; }}
  .metric .lbl {{ font-size: 12px; color: #94a3b8; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0 22px; font-size: 13px; }}
  th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: 8px 10px; }}
  td {{ border-bottom: 1px solid #1e293b; padding: 8px 10px; }}
  .sev-h {{ color: #ef4444; font-weight: 600; }} .sev-m {{ color: #f59e0b; }} .sev-l {{ color: #3b82f6; }}
  .sev-dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }}
  .sev-high {{ background:#ef4444; }} .sev-medium {{ background:#f59e0b; }} .sev-low {{ background:#3b82f6; }}
  .err {{ color: #ef4444; }} .warn {{ color: #f59e0b; margin: 8px 0; }}
  .empty {{ color: #64748b; text-align: center; }}
  code {{ font-size: 11px; color: #94a3b8; word-break: break-all; }}
  h2 {{ color: #f8fafc; font-size: 16px; margin: 18px 0 6px; }}
</style>
</head>
<body>
<h1>{esc(agg["title"])}</h1>
<div class="sub">生成于 {esc(agg["generated_at"])} · {agg["db_count"]} 个证据库</div>
<div class="metrics">
  <div class="metric"><div class="num">{agg["total_events"]}</div><div class="lbl">总事件</div></div>
  <div class="metric"><div class="num">{agg["total_findings"]}</div><div class="lbl">风险发现</div></div>
  <div class="metric"><div class="num">{agg["sev_dist"].get("high", 0)}</div><div class="lbl">High</div></div>
  <div class="metric"><div class="num">{len(agg.get("agents", {}))}</div><div class="lbl">Agent 数</div></div>
</div>
{warn_html}
<h2>各库画像</h2>
<table>
  <thead><tr><th>证据库</th><th>事件</th><th>Agent / Model</th><th>风险</th><th>严重度</th><th>链 / 锚定</th></tr></thead>
  <tbody>{profiles_html}</tbody>
</table>
<h2>风险类别排行</h2>
<table><thead><tr><th>类别</th><th>次数</th></tr></thead><tbody>{cat_rows}</tbody></table>
<h2>高危事件 Top</h2>
<table><thead><tr><th>库</th><th>级别</th><th>类别</th><th>标题</th><th>上下文</th></tr></thead><tbody>{top_html}</tbody></table>
</body>
</html>"""


def render_agg_text(agg: Dict[str, Any]) -> str:
    """文本摘要（CLI stdout 用）。"""
    lines = [f"== {agg['title']} ==", f"库数: {agg['db_count']} | 事件: {agg['total_events']} | 风险: {agg['total_findings']}"]
    if agg.get("error_dbs"):
        lines.append("✘ 无法读取: " + ", ".join(agg["error_dbs"]))
    if agg.get("warn_dbs"):
        lines.append("⚠ 链异常库: " + ", ".join(agg["warn_dbs"]))
    for r in agg["cat_rank"]:
        lines.append(f"  {r['category_name']}: {r['count']}")
    for p in agg["profiles"]:
        if p.get("error"):
            lines.append(f"- {p['db']}: {p['error']}")
            continue
        meta = p.get("meta") or {}
        lines.append(f"- {p['db']}: {p.get('event_count', 0)} 事件, "
                     f"{p.get('finding_count', 0)} 风险 "
                     f"(H{p.get('sev_dist', {}).get('high', 0)}/"
                     f"M{p.get('sev_dist', {}).get('medium', 0)}/"
                     f"L{p.get('sev_dist', {}).get('low', 0)}) "
                     f"agent={meta.get('agent', '?')} "
                     f"[{'链OK' if p.get('chain_ok') else '链异常'}"
                     f"{'·锚定' if p.get('anchored') else ''}]")
    return "\n".join(lines)