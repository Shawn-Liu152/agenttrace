"""示例：把 OpenAI Responses API / LangGraph 的运行时数据接入 AgentTrace 取证。

零依赖红线：AgentTrace 不做网络请求、不 import openai——你只需要把你
SDK 返回的结构化数据传进来（dict 即可），转换后写入证据链。

OpenAI Responses API（流式）：
    from openai import OpenAI
    client = OpenAI()
    stream = client.responses.create(model="gpt-5", input=[...], stream=True)
    n = ingest_openai_response_events(store, (e.model_dump() for e in stream))

LangGraph（状态/检查点）：
    from langgraph.checkpoint import ...
    state = graph.get_state(config)   # state["messages"] 是消息数组
    n = ingest_langgraph_state(store, [m.__dict__/model_dump() for m in state["messages"]])
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.adapters import ingest_langgraph_state, ingest_messages
from agenttrace.store import EvidenceStore

DB = "adapter_demo.db"
if os.path.exists(DB):
    os.remove(DB)
store = EvidenceStore(DB)

# 1. OpenAI Chat Completions 消息数组（最简单形态）
chat_messages = [
    {"role": "user", "content": "帮我看看服务器上有什么"},
    {"role": "assistant", "content": "我先列目录",
     "tool_calls": [{"id": "call_1",
                     "function": {"name": "shell", "arguments": '{"cmd": "ls -la"}'}}]},
    {"role": "tool", "tool_call_id": "call_1", "name": "shell", "content": "app.py data/"},
    {"role": "assistant", "content": "根目录有 app.py 和 data/"},
]
n = ingest_messages(store, chat_messages, agent="hermes", model="gpt-5")
print(f"[1] Chat Completions 摄入 {n} 条事件")

# 2. LangGraph 消息数组
lg_messages = [
    {"type": "human", "content": "删除旧日志"},
    {"type": "ai", "content": "执行删除",
     "tool_calls": [{"name": "shell", "args": {"cmd": "rm -rf /data/old"}, "id": "t1"}]},
    {"type": "tool", "name": "shell", "content": "deleted"},
    {"type": "ai", "content": "已清理"},
]
n2 = ingest_langgraph_state(store, lg_messages, agent="hermes", model="claude-4")
print(f"[2] LangGraph 摄入 {n2} 条事件")

# 3. 验证证据链 + 风险扫描 + 报告
ok, problems, total = store.verify()
print(f"[3] 链验证: {'OK' if ok else 'FAIL'} ({total} 事件)")
from agenttrace.analyzer import analyze_chain
from agenttrace.report import render_report_file
findings = analyze_chain(store.all_events())
print(f"[4] 风险发现: {len(findings)} 条 -> "
      + ", ".join(f.title for f in findings))
render_report_file(store.all_events(), findings, store.all_meta(),
                   "adapter_demo.html", title="适配器示例")
print("[5] 报告: adapter_demo.html")
store.close()