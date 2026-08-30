"""复现评审报告的 5 类攻击，验证 AgentTrace 当前版本（修复前）的行为。"""
import sys, os, json, tempfile
sys.path.insert(0, r"C:\Users\19826\Desktop\AgentTrace")
from agenttrace.store import EvidenceStore
from agenttrace.recorder import Recorder, make_session_start, make_user_message, make_tool_call, make_tool_result
from agenttrace.chain import append_event

tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "e.db")
print("tmp:", tmp)

def build_db(path):
    s = EvidenceStore(path)
    r = Recorder(s)
    s.set_meta("agent", "hermes")
    s.set_meta("model", "gpt-5.6-luna")
    r.ingest(make_session_start(agent="hermes", model="gpt-5.6-luna", tools=["terminal"]))
    r.ingest(make_user_message("帮我清理旧项目"))
    r.ingest(make_tool_call("terminal", {"command": "ls /data/old"}))
    r.ingest(make_tool_result("terminal", "a b c"))
    r.ingest(make_tool_call("terminal", {"command": "rm -rf /data/old"}))   # ← 高危
    r.ingest(make_tool_result("terminal", "deleted"))
    s.close()
    return path

# ---- 攻击 A：末尾截断（删除尾部 rm -rf 及其结果）----
dbA = build_db(os.path.join(tmp, "A.db"))
s = EvidenceStore(dbA)
s.conn.execute("DELETE FROM events WHERE seq >= 4"); s.conn.commit()
ok, problems, n = s.verify()
print(f"A 末尾截断: verify={ok} problems={problems} count={n}  → {'❌ 穿透' if ok else '✅ 检出'}")
s.close()

# ---- 攻击 B：整链重算（改 rm -rf 为 ls -la 后重算全链并回写）----
dbB = build_db(os.path.join(tmp, "B.db"))
s = EvidenceStore(dbB)
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
s.conn.commit()
ok, problems, n = s.verify()
print(f"B 整链重算: verify={ok} problems={problems} count={n} → {'❌ 穿透' if ok else '✅ 检出'}")
s.close()

# ---- 攻击 C：元信息篡改 ----
dbC = build_db(os.path.join(tmp, "C.db"))
s = EvidenceStore(dbC)
s.set_meta("agent", "totally-innocent-agent")
ok, problems, n = s.verify()
print(f"C 元信息篡改: verify={ok} problems={problems} count={n} → {'❌ 穿透' if ok else '✅ 检出'}")
s.close()

# ---- 攻击 D：重放覆盖 ----
dbD = build_db(os.path.join(tmp, "D.db"))
s = EvidenceStore(dbD)
old_ev = s.get(1)
s.conn.execute("INSERT INTO events (seq, event_id, ts, type, actor, content, meta, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
    (old_ev["seq"] + 100, old_ev.get("event_id"), old_ev["ts"], old_ev["type"], old_ev["actor"],
     json.dumps(old_ev["content"], ensure_ascii=False), None, old_ev.get("prev_hash"), old_ev["hash"]))
s.conn.commit()
ok, problems, n = s.verify()
print(f"D 重放覆盖: verify={ok} problems={problems} count={n} → {'❌ 穿透' if ok else '✅ 检出'}")
s.close()

# ---- 攻击 E：时间戳伪造 ----
dbE = build_db(os.path.join(tmp, "E.db"))
s = EvidenceStore(dbE)
s.conn.execute("UPDATE events SET ts=? WHERE seq=5", (820000000.0,))  # 1996 年
s.conn.commit()
ok, problems, n = s.verify()
print(f"E 时间戳伪造: verify={ok} problems={problems} count={n} → {'❌ 穿透' if ok else '✅ 检出'}")
s.close()