"""AgentTrace Showcase：完整事故复盘取证演示（v0.9 全功能链）。

生成一套"AI Agent 事故"的完整取证产物到桌面 AgentTrace_showcase/：
  1. evidence.db          —— SHA-256 哈希链证据库（18 条事件，拒覆盖）
  2. Ed25519 锚定          —— 私有签名 + 公钥（验证端无私钥）
  3. RFC3161 时间戳        —— mock TSA（本机），TSQ/TSR 落盘
  4. 审计报告 report.html  —— 时间线回放 + 7 项风险命中 + 锚定徽章
  5. 脱敏报告 report_redacted.html（分发给外部，密钥打码）
  6. 证据包 evidence-bundle.zip（链+锚定+公钥+报告+manifest 一体）
  7. 聚合报告 aggregate.html（两个事故库跨库画像）

用法：python tools/make_showcase.py
"""
import json
import os
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

OUT = os.path.join(os.path.expanduser("~"), "Desktop", "AgentTrace_showcase")

# 让 tests 可导入（mock TSA 服务）
sys.path.insert(0, os.path.join(ROOT, "tests"))
from test_tsa import TSAHttpServer  # noqa: E402


def run(args, **kw):
    env = {**os.environ, "PYTHONPATH": ROOT}
    r = subprocess.run([sys.executable, "-m", "agenttrace"] + args,
                       capture_output=True, text=True, env=env, timeout=180, **kw)
    if r.returncode != 0:
        print(r.stdout + r.stderr)
        raise SystemExit(f"命令失败: {' '.join(args)}")
    return r.stdout


def main():
    os.makedirs(OUT, exist_ok=True)
    sample = os.path.join(ROOT, "examples", "sample_session.jsonl")

    print("== 1/8 初始化证据库 + Ed25519 密钥 ==")
    run(["seal", "keygen", "--db", os.path.join(OUT, "evidence.db")])
    run(["init", "--db", os.path.join(OUT, "evidence.db"),
         "--agent", "hermes", "--model", "gpt-5.6-luna"])

    print("== 2/8 摄入 18 条事故事件（哈希链）==")
    run(["record", sample, "--db", os.path.join(OUT, "evidence.db")])

    print("== 3/8 Ed25519 签名锚定 ==")
    run(["seal", "seal", "--db", os.path.join(OUT, "evidence.db")])

    print("== 4/8 完整性验证（绑定公钥）==")
    pub = open(os.path.join(OUT, "evidence.db.anchor.json"), encoding="utf-8").read()
    pub = json.loads(pub)["public_key"]
    out = run(["seal", "verify", "--db", os.path.join(OUT, "evidence.db"),
               "--public-key", pub])
    print("   ", [l for l in out.splitlines() if "✔" in l][0])

    print("== 5/8 RFC3161 时间戳（mock TSA）==")
    with TSAHttpServer() as ts:
        run(["tsa", "stamp", "--db", os.path.join(OUT, "evidence.db"),
             "--tsa-url", ts.url])

    print("== 6/8 报告（普通 + 脱敏）==")
    run(["report", "--db", os.path.join(OUT, "evidence.db"),
         "--out", os.path.join(OUT, "report.html"),
         "--title", "AI Agent 事故复盘：旧项目清理中的密钥外发"])
    run(["report", "--db", os.path.join(OUT, "evidence.db"),
         "--out", os.path.join(OUT, "report_redacted.html"),
         "--title", "AI Agent 事故复盘（脱敏版，供外部）", "--redact"])

    print("== 7/8 证据包（含脱敏报告）==")
    out = run(["bundle", "export", "--db", os.path.join(OUT, "evidence.db"),
               "--out", os.path.join(OUT, "evidence-bundle.zip"), "--redact"])
    print("   ", [l for l in out.splitlines() if "📦" in l][0])

    print("== 8/8 跨库聚合（另一个事故库）==")
    second = os.path.join(OUT, "second.db")
    run(["init", "--db", second, "--agent", "hermes-pi", "--model", "claude-4"])
    run(["record", sample, "--db", second])
    run(["aggregate", "--dbs", f"{os.path.join(OUT, 'evidence.db')},{second}",
         "--out", os.path.join(OUT, "aggregate.html")])

    print("\n✅ Showcase 完成，产物目录：")
    for f in sorted(os.listdir(OUT)):
        p = os.path.join(OUT, f)
        print(f"  {f}  ({os.path.getsize(p):,} bytes)")


if __name__ == "__main__":
    main()