"""AgentTrace HTML 报告：生成可交互的时间线回放审计报告。

单文件 HTML（内嵌 CSS/JS，零外部依赖），包含：
  - 顶部统计卡：事件数、工具调用数、风险统计、会话时长
  - 时间线：按时间先后的事件泳道，风险事件高亮标记
  - 风险面板：high/medium/low 分级列出全部发现
  - 链完整性徽章：显示验证结果（链完整 ✅ / 篡改 ⚠️）
  - 交互：过滤事件类型、搜索、展开/折叠详情、复制哈希
"""

from __future__ import annotations

import datetime
import html
import json
import time
from typing import Any, Dict, List, Optional

from .analyzer import analyze_chain, summarize, Finding
from .chain import verify_chain

# ---------------------------------------------------------------------------
# 渲染辅助
# ---------------------------------------------------------------------------

TYPE_LABELS = {
    "session_start": "会话开始",
    "user_message": "用户",
    "agent_message": "Agent",
    "tool_call": "工具调用",
    "tool_result": "工具结果",
    "error": "错误",
    "checkpoint": "检查点",
    "session_end": "会话结束",
}

TYPE_COLORS = {
    "session_start": "#6366f1",
    "user_message": "#0ea5e9",
    "agent_message": "#10b981",
    "tool_call": "#f59e0b",
    "tool_result": "#84cc16",
    "error": "#ef4444",
    "checkpoint": "#8b5cf6",
    "session_end": "#64748b",
}

SEV_COLORS = {"high": "#ef4444", "medium": "#f59e0b", "low": "#3b82f6"}


def _esc(v: Any) -> str:
    return html.escape(str(v), quote=True)


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        return f"{ts:.3f}"


def _content_render(ev: Dict[str, Any]) -> str:
    """把事件内容渲染为展示 HTML（安全转义）。"""
    c = ev.get("content")
    if isinstance(c, str):
        return _esc(c)
    if isinstance(c, dict):
        parts = []
        for k, v in c.items():
            if isinstance(v, str) and len(v) > 600:
                v = v[:600] + "… (已截断)"
            parts.append(
                f'<div class="kv"><span class="k">{_esc(k)}</span>'
                f'<span class="v">{_esc(json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v)}</span></div>'
            )
        return "".join(parts)
    return _esc(json.dumps(c, ensure_ascii=False))


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------

def generate_report(
    events: List[Dict[str, Any]],
    findings: List[Finding],
    meta: Dict[str, Any],
    chain_ok: bool,
    chain_problems: List[str],
    title: str = "AgentTrace 审计报告",
    anchored: Optional[bool] = None,
    anchor_info: str = "",
) -> str:
    """生成完整 HTML 报告字符串。"""
    total = len(events)
    tool_calls = sum(1 for e in events if e.get("type") == "tool_call")
    errors = sum(1 for e in events if e.get("type") == "error")
    summ = summarize(findings)

    if events:
        t0 = min(e["ts"] for e in events)
        t1 = max(e["ts"] for e in events)
        duration = t1 - t0
    else:
        t0 = t1 = duration = 0

    # ---- 时间线条目 ----
    timeline_items = []
    for ev in events:
        et = ev.get("type", "?")
        label = TYPE_LABELS.get(et, et)
        color = TYPE_COLORS.get(et, "#94a3b8")
        sev_badge = ""
        ev_findings = [f for f in findings if f.seq == ev.get("seq")]
        if ev_findings:
            worst = max(ev_findings, key=lambda f: {"high": 3, "medium": 2, "low": 1}[f.severity])
            sev_badge = (
                f'<span class="sev-badge" style="background:{SEV_COLORS[worst.severity]}">'
                f'⚠ {worst.severity.upper()} ×{len(ev_findings)}</span>'
            )
        timeline_items.append(
            f"""
            <div class="tl-item" data-type="{_esc(et)}">
              <div class="tl-marker" style="background:{color}"></div>
              <div class="tl-body">
                <div class="tl-head">
                  <span class="tl-type" style="color:{color}">{_esc(label)}</span>
                  <span class="tl-time">{_esc(_fmt_ts(ev['ts']))}</span>
                  <span class="tl-actor">{_esc(ev.get('actor',''))}</span>
                  {sev_badge}
                  <span class="tl-seq">#{ev['seq']}</span>
                </div>
                <div class="tl-content">{_content_render(ev)}</div>
                <details class="tl-chain">
                  <summary>证据哈希</summary>
                  <code class="hash-line">prev: {_esc(ev.get('prev_hash') or '(none)')}</code>
                  <code class="hash-line">hash: {_esc(ev.get('hash') or '(none)')}</code>
                </details>
              </div>
            </div>
            """
        )
    timeline_html = "\n".join(timeline_items) if timeline_items else '<div class="empty">无事件</div>'

    # ---- 风险面板 ----
    if findings:
        finding_rows = []
        for f in findings:
            finding_rows.append(
                f"""
                <tr class="sev-{f.severity}">
                  <td><span class="sev-dot" style="background:{SEV_COLORS[f.severity]}"></span>{f.severity.upper()}</td>
                  <td>{_esc(f.category_name)}</td>
                  <td>{_esc(f.title)}</td>
                  <td class="f-seq">#{f.seq}</td>
                  <td class="f-detail"><code>{_esc(f.detail)}</code></td>
                </tr>
                """
            )
        findings_html = (
            '<table class="findings"><thead><tr>'
            "<th>级别</th><th>类别</th><th>风险</th><th>事件</th><th>上下文</th>"
            "</tr></thead><tbody>" + "\n".join(finding_rows) + "</tbody></table>"
        )
    else:
        findings_html = '<div class="empty">✅ 未检测到高风险行为</div>'

    # ---- 链状态徽章 ----
    if chain_ok:
        chain_badge = (
            '<span class="chain-badge ok">✅ 证据链完整 · ' + str(total) + " 条事件全部验证通过</span>"
        )
    else:
        chain_badge = (
            '<span class="chain-badge bad">⚠️ 证据链异常！' + str(len(chain_problems)) + " 处问题</span>"
            + "<ul class='chain-problems'>"
            + "".join(f"<li>{_esc(p)}</li>" for p in chain_problems[:10])
            + "</ul>"
        )
    # 锚定状态徽章（锚定 = 可对抗整链重写/截断；未锚定 = 仅自洽校验）
    if anchored is None:
        anchor_badge = ""
    elif anchored:
        anchor_badge = (
            '<span class="chain-badge ok" style="margin-left:8px">🔐 外部锚定有效</span>'
            + (f'<span class="sub" style="margin-left:8px">{_esc(anchor_info)}</span>' if anchor_info else "")
        )
    else:
        anchor_badge = (
            '<span class="chain-badge bad" style="margin-left:8px">⚠️ 未锚定：仅自洽校验，'
            "无法对抗整链重写/末尾截断/元信息篡改</span>"
        )

    # ---- meta 面板 ----
    meta_items = "".join(
        f'<div class="kv"><span class="k">{_esc(k)}</span><span class="v">{_esc(json.dumps(v, ensure_ascii=False))}</span></div>'
        for k, v in meta.items()
    ) if meta else '<div class="empty">无会话元信息</div>'

    # ---- 过滤按钮（事件类型）----
    types_present = sorted({e.get("type") for e in events})
    filter_btns = "".join(
        f'<button class="fbtn" data-type="{_esc(t)}">{_esc(TYPE_LABELS.get(t, t))}</button>'
        for t in types_present
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: "Segoe UI", "Microsoft YaHei", sans-serif; background: #0f172a; color: #e2e8f0; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px 20px 60px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .sub {{ color: #94a3b8; font-size: 13px; margin-bottom: 20px; }}

  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .stat {{ background: #1e293b; border-radius: 10px; padding: 14px 16px; }}
  .stat .n {{ font-size: 26px; font-weight: 700; }}
  .stat .l {{ color: #94a3b8; font-size: 12px; }}
  .stat.hi .n {{ color: #ef4444; }}
  .stat.md .n {{ color: #f59e0b; }}
  .stat.ok .n {{ color: #10b981; }}

  .panel {{ background: #1e293b; border-radius: 12px; padding: 18px 20px; margin-bottom: 24px; }}
  .panel h2 {{ font-size: 15px; margin-bottom: 12px; color: #cbd5e1; }}

  .chain-badge {{ display: inline-block; padding: 6px 14px; border-radius: 999px; font-size: 13px; font-weight: 600; }}
  .chain-badge.ok {{ background: #052e16; color: #4ade80; border: 1px solid #166534; }}
  .chain-badge.bad {{ background: #450a0a; color: #f87171; border: 1px solid #991b1b; }}
  .chain-problems {{ margin-top: 8px; color: #fca5a5; font-size: 12px; padding-left: 18px; }}

  .filters {{ margin-bottom: 14px; display: flex; flex-wrap: wrap; gap: 6px; }}
  .fbtn {{ background: #334155; color: #e2e8f0; border: none; border-radius: 999px; padding: 4px 12px; font-size: 12px; cursor: pointer; }}
  .fbtn.active {{ background: #6366f1; }}
  .search {{ width: 100%; padding: 8px 12px; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; margin-bottom: 14px; font-size: 13px; }}

  .tl-item {{ display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid #1e293b; }}
  .tl-marker {{ width: 10px; min-width: 10px; height: 10px; border-radius: 50%; margin-top: 6px; }}
  .tl-body {{ flex: 1; min-width: 0; }}
  .tl-head {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .tl-type {{ font-weight: 700; font-size: 13px; }}
  .tl-time {{ color: #64748b; font-size: 12px; }}
  .tl-actor {{ background: #334155; color: #cbd5e1; border-radius: 999px; padding: 1px 8px; font-size: 11px; }}
  .tl-seq {{ color: #475569; font-size: 11px; }}
  .sev-badge {{ border-radius: 999px; padding: 1px 8px; font-size: 11px; color: #fff; font-weight: 700; }}
  .tl-content {{ margin-top: 6px; font-size: 13px; color: #cbd5e1; white-space: pre-wrap; word-break: break-all; }}
  .tl-content .kv {{ display: flex; gap: 8px; margin: 2px 0; }}
  .tl-content .k {{ color: #94a3b8; min-width: 90px; }}
  .tl-chain summary {{ color: #64748b; font-size: 11px; cursor: pointer; margin-top: 6px; }}
  .hash-line {{ display: block; font-size: 11px; color: #475569; word-break: break-all; font-family: Consolas, monospace; }}

  .findings {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  .findings th {{ text-align: left; color: #94a3b8; padding: 6px 8px; border-bottom: 1px solid #334155; }}
  .findings td {{ padding: 6px 8px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  .sev-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }}
  .f-detail code {{ color: #94a3b8; font-size: 11px; word-break: break-all; }}

  .empty {{ color: #64748b; font-size: 13px; padding: 12px 0; }}
  .hidden {{ display: none !important; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>{_esc(title)}</h1>
  <div class="sub">AgentTrace 证据链审计 · 生成于 {_esc(_fmt_ts(time.time()))}</div>

  <div class="stats">
    <div class="stat"><div class="n">{total}</div><div class="l">事件总数</div></div>
    <div class="stat"><div class="n">{tool_calls}</div><div class="l">工具调用</div></div>
    <div class="stat {'hi' if errors else 'ok'}"><div class="n">{errors}</div><div class="l">错误</div></div>
    <div class="stat {'hi' if summ['by_severity'].get('high',0) else 'ok'}"><div class="n">{summ['by_severity'].get('high',0)}</div><div class="l">高风险</div></div>
    <div class="stat {'md' if summ['by_severity'].get('medium',0) else 'ok'}"><div class="n">{summ['by_severity'].get('medium',0)}</div><div class="l">中风险</div></div>
    <div class="stat"><div class="n">{duration:.1f}s</div><div class="l">会话时长</div></div>
  </div>

  <div class="panel">
    <h2>🔗 证据链完整性</h2>
    {chain_badge}
    {anchor_badge}
  </div>

  <div class="panel">
    <h2>📋 会话信息</h2>
    {meta_items}
  </div>

  <div class="panel">
    <h2>⚠️ 风险发现（{summ['total']}）</h2>
    {findings_html}
  </div>

  <div class="panel">
    <h2>🕐 事件时间线（{total}）</h2>
    <input class="search" id="search" placeholder="搜索事件内容…">
    <div class="filters" id="filters">
      <button class="fbtn active" data-type="__all__">全部</button>
      {filter_btns}
    </div>
    <div id="timeline">{timeline_html}</div>
  </div>
</div>

<script>
  const search = document.getElementById('search');
  const items = [...document.querySelectorAll('.tl-item')];
  let activeType = '__all__';

  function apply() {{
    const q = search.value.toLowerCase();
    items.forEach(it => {{
      const typeOk = activeType === '__all__' || it.dataset.type === activeType;
      const textOk = !q || it.textContent.toLowerCase().includes(q);
      it.classList.toggle('hidden', !(typeOk && textOk));
    }});
  }}

  document.getElementById('filters').addEventListener('click', e => {{
    if (!e.target.classList.contains('fbtn')) return;
    document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
    e.target.classList.add('active');
    activeType = e.target.dataset.type;
    apply();
  }});

  search.addEventListener('input', apply);
</script>
</body>
</html>
"""


def render_report_file(
    events: List[Dict[str, Any]],
    findings: List[Finding],
    meta: Dict[str, Any],
    out_path: str,
    title: str = "AgentTrace 审计报告",
    anchored: Optional[bool] = None,
    anchor_info: str = "",
) -> str:
    """生成报告并写入文件，返回写入路径。"""
    chain_ok, chain_problems = verify_chain(events)
    html_str = generate_report(events, findings, meta, chain_ok, chain_problems, title,
                               anchored=anchored, anchor_info=anchor_info)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_str)
    return out_path