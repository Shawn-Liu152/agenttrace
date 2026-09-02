"""AgentTrace 性能基准：大规模证据链的 append / verify / analyze 耗时。

用法：python tools/benchmark.py [--events 100000]
输出量化数据（简历/README 可引用）：
  - 10 万事件追加（哈希链构建）耗时与吞吐
  - 全链 verify 耗时
  - 风险扫描耗时
  - SQLite 库文件大小
"""
import argparse
import sys

# Windows CI cp1252 控制台：Unicode 符号直接 print 会炸——强制 UTF-8
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
import json
import os
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agenttrace.analyzer import analyze_chain
from agenttrace.chain import verify_chain
from agenttrace.recorder import make_tool_call, make_tool_result, make_user_message
from agenttrace.store import EvidenceStore

MIX = [
    make_user_message("检查服务器状态并执行例行清理"),
    make_tool_call("terminal", {"command": "df -h && ls /data"}),
    make_tool_result("terminal", "OK"),
    make_tool_call("read_file", {"path": "/srv/app/config.yml"}),
    make_tool_result("read_file", "config loaded"),
]


def bench(events_n: int) -> dict:
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "bench.db")
    store = EvidenceStore(db)
    store.set_meta("agent", "bench-agent")
    store.set_meta("model", "bench-model")

    t0 = time.perf_counter()
    n = 0
    with store.batch():  # v1.0：批量模式（延迟 commit + 锚定合并）
        while n < events_n:
            for ev in MIX:
                if n >= events_n:
                    break
                store.append(ev)
                n += 1
    t_append = time.perf_counter() - t0

    events = store.all_events()
    t0 = time.perf_counter()
    ok, problems, total = store.verify()
    t_verify = time.perf_counter() - t0

    t0 = time.perf_counter()
    findings = analyze_chain(events)
    t_analyze = time.perf_counter() - t0

    size = os.path.getsize(db)
    store.close()
    return {
        "events": n,
        "append_sec": round(t_append, 3),
        "append_eps": round(n / t_append, 0),
        "verify_sec": round(t_verify, 3),
        "analyze_sec": round(t_analyze, 3),
        "db_size_bytes": size,
        "chain_ok": ok,
        "findings": len(findings),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=100_000)
    args = ap.parse_args()
    r = bench(args.events)
    print(json.dumps(r, indent=2))
    print(f"\n事件 {r['events']:,} | 追加 {r['append_sec']}s ({r['append_eps']:,.0f} 条/s) "
          f"| verify {r['verify_sec']}s | analyze {r['analyze_sec']}s "
          f"| DB {r['db_size_bytes']/1048576:.1f}MB | 链OK={r['chain_ok']}")


if __name__ == "__main__":
    main()