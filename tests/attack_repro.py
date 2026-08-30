"""5 类攻击复现与检出验证（v0.3 锚定版）。

v0.1 基线：A/B/C 穿透（2/5 检出）。
v0.2 起（外部锚定）：A/B/C 全部转为检出（5/5）。
本脚本作为 CI 门禁：任何回归都会让退出码非 0。

同时演示"未锚定库"的诚实警告行为（退出码语义由 CLI 层保证）。
"""
import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agenttrace.store import EvidenceStore
from agenttrace.recorder import Recorder, make_session_start, make_user_message, make_tool_call, make_tool_result
from agenttrace.chain import append_event
from agenttrace.anchor import AnchorKey, anchor_state

tmp = tempfile.mkdtemp()
key = AnchorKey.generate()
print("tmp:", tmp)

def build_db(path):
    s = EvidenceStore(path, anchor_key=key)
    r = Recorder(s)
    s.set_meta("agent", "hermes"); s.set_meta("model", "gpt-5.6-luna")
    r.ingest(make_session_start(agent="hermes", model="gpt-5.6-luna", tools=["terminal"]))
    r.ingest(make_user_message("帮我清理旧项目"))
    r.ingest(make_tool_call("terminal", {"command": "ls /data/old"}))
    r.ingest(make_tool_result("terminal", "a b c"))
    r.ingest(make_tool_call("terminal", {"command": "rm -rf /data/old"}))   # ← 高危
    r.ingest(make_tool_result("terminal", "deleted"))
    s.close()

def verify_db(path):
    s = EvidenceStore(path, anchor_key=key)
    ok, problems, n = s.verify()
    s.close()
    real = [p for p in problems if not p.startswith("未锚定")]
    return ok, real, n

results = []
def run(name, path, attack):
    build_db(path)
    attack(path)
    ok, real, n = verify_db(path)
    detected = not ok and len(real) > 0
    results.append(detected)
    print(f"{name}: {'✅ 检出' if detected else '❌ 穿透'}  problems={real[:1]}")

# A 末尾截断
def a(p):
    s = EvidenceStore(p, anchor_key=key); s.conn.execute("DELETE FROM events WHERE seq >= 4"); s.conn.commit(); s.close()
run("A 末尾截断", os.path.join(tmp, "A.db"), a)

# B 整链重算
def b(p):
    s = EvidenceStore(p, anchor_key=key)
    evs = s.all_events()
    evs[4]["content"] = {"name": "terminal", "arguments": {"command": "ls -la /data/old"}}
    newchain = []
    for ev in evs:
        e = {k: v for k, v in ev.items() if k not in ("prev_hash", "hash")}
        newchain.append(append_event(newchain, e))
    for ev in newchain:
        s.conn.execute("UPDATE events SET content=?, prev_hash=?, hash=? WHERE seq=?",
            (json.dumps(ev["content"], sort_keys=True, separators=(",", ":")),
             ev.get("prev_hash"), ev["hash"], ev["seq"]))
    s.conn.commit(); s.close()
run("B 整链重算", os.path.join(tmp, "B.db"), b)

# C 元信息篡改
def c(p):
    s = EvidenceStore(p, anchor_key=key)
    s.conn.execute("UPDATE meta SET value='\"totally-innocent-agent\"' WHERE key='agent'")
    s.conn.commit(); s.close()
run("C 元信息篡改", os.path.join(tmp, "C.db"), c)

# D 重放覆盖
def d(p):
    s = EvidenceStore(p, anchor_key=key)
    old = s.get(1)
    s.conn.execute("INSERT INTO events (seq, event_id, ts, type, actor, content, meta, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
        (old["seq"] + 100, old.get("event_id"), old["ts"], old["type"], old["actor"],
         json.dumps(old["content"], ensure_ascii=False), None, old.get("prev_hash"), old["hash"]))
    s.conn.commit(); s.close()
run("D 重放覆盖", os.path.join(tmp, "D.db"), d)

# E 时间戳伪造
def e(p):
    s = EvidenceStore(p, anchor_key=key)
    s.conn.execute("UPDATE events SET ts=? WHERE seq=5", (820000000.0,))
    s.conn.commit(); s.close()
run("E 时间戳伪造", os.path.join(tmp, "E.db"), e)

# 正常库应通过
g = os.path.join(tmp, "G.db"); build_db(g)
ok, _, n = verify_db(g)
print(f"正常锚定库: {'✅ 通过' if ok else '❌ 异常'} ({n} 条)")
results.append(ok)

# 未锚定库必须显式警告（不能假装安全）
u = os.path.join(tmp, "U.db")
s = EvidenceStore(u)
s.set_meta("agent", "x")
r = Recorder(s); r.ingest(make_session_start(agent="x"))
ok, problems, n = s.verify(); s.close()
warned = any("未锚定" in p for p in problems)
print(f"未锚定库: {'✅ 显式警告' if warned else '❌ 未警告'}")
results.append(warned)

total_ok = all(results)
print(f"\n=== 门禁结果: {'全部通过' if total_ok else '存在失败'} ({sum(results)}/{len(results)}) ===")
sys.exit(0 if total_ok else 1)