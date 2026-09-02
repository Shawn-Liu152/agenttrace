"""示例：真实 Agent 运行时自动采集（v1.2 新增 instrument 钩子，零侵入）。

adapter_demo.py 演示的是"数据已经拿到手，怎么转成证据事件"；本示例演示
更贴近实战的形态：**不改 Agent 业务代码、不 import 任何 SDK 内部实现**，
在运行时把 OpenAI 兼容客户端和工具函数"包一层"，之后所有调用自动入证据链。

为保证离线可跑（CI 也会执行本文件），下面用一个鸭子类型的假客户端；
真实环境把 FakeOpenAIClient 换成 `OpenAI()` 即可，其余代码一行不改：

    from openai import OpenAI
    client = OpenAI()
    instrument_chat_completions(client, store, agent="hermes", model="gpt-x")
    client.chat.completions.create(model="gpt-x", messages=[...])  # 自动入链
"""

import json
import os
import sys

# Windows 控制台 cp1252 兼容（CI 血泪教训：模块级 reconfigure）
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.analyzer import analyze_chain
from agenttrace.instrument import (
    instrument_chat_completions, trace_tool, traced_session,
)
from agenttrace.report import render_report_file
from agenttrace.store import EvidenceStore


# ---------------------------------------------------------------------------
# 离线假客户端：结构刻意模仿 openai SDK（嵌套对象 + model_dump），不联网
# ---------------------------------------------------------------------------


class _Obj:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def model_dump(self):
        out = {}
        for k, v in vars(self).items():
            if k.startswith("_"):
                continue
            out[k] = v.model_dump() if hasattr(v, "model_dump") else v
        return out


class _Completions:
    def create(self, model=None, messages=None, stream=False):
        # 一个会调 shell 工具、再总结的迷你"Agent"
        if stream:
            return iter([
                _Obj(choices=[_Obj(delta=_Obj(content="根目录有 "))]),
                _Obj(choices=[_Obj(delta=_Obj(content="app.py 和 data/"))]),
            ])
        last_user = next((m["content"] for m in reversed(messages)
                          if m["role"] == "user"), "")
        if "看看" in last_user:
            return _Obj(choices=[_Obj(message=_Obj(
                content=None,
                tool_calls=[_Obj(id="call_1", function=_Obj(
                    name="shell", arguments=json.dumps({"cmd": "ls -la"})))]))])
        return _Obj(choices=[_Obj(message=_Obj(content="根目录有 app.py 和 data/",
                                               tool_calls=None))])


class _Chat:
    completions = _Completions()


class FakeOpenAIClient:
    chat = _Chat()


# 被 Agent 调用的"工具"：装饰器一行接入
def make_tools(store):
    @trace_tool(store, "shell")
    def shell(cmd):
        return f"$ {cmd}\napp.py\ndata/"

    return shell


def main():
    db = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "runtime_hook_demo.db")
    for p in (db, db + ".anchor.json"):
        if os.path.exists(p):
            os.remove(p)

    store = EvidenceStore(db)
    client = FakeOpenAIClient()
    shell = make_tools(store)

    # ① 3 行接入：包装客户端，之后每次 create 自动入链，返回值不变
    handle = instrument_chat_completions(
        client, store, agent="hermes", model="gpt-fake")

    with traced_session(store, agent="hermes", model="gpt-fake",
                        tools=["shell"]):
        # 第一轮：模型决定调工具
        r1 = client.chat.completions.create(messages=[
            {"role": "user", "content": "帮我看看服务器根目录"}])
        tc = r1.choices[0].message.tool_calls[0]
        args = json.loads(tc.function.arguments)
        result = shell(**args)  # ② 工具调用自动记 tool_call/tool_result
        # 第二轮：把工具结果回灌模型，得到总结（流式，逐块透传，消费完自动入链）
        chunks = list(client.chat.completions.create(messages=[
            {"role": "tool", "tool_call_id": tc.id, "name": "shell",
             "content": result},
            {"role": "user", "content": "总结一下"}], stream=True))
        assert len(chunks) == 2  # 业务侧照常逐块消费，采集对调用方透明

    handle.restore()  # ③ 还原客户端（也可用 with 语法）

    # ④ 证据链自检 + 风险扫描 + HTML 报告
    ok, problems, total = store.verify()
    findings = analyze_chain(store.all_events())
    report = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "runtime_hook_demo.html")
    render_report_file(store.all_events(), findings, store.all_meta(),
                       report, title="运行时钩子采集示例")

    print(f"采集事件 {total} 条，哈希链验证: {'OK' if ok else 'FAIL'}")
    if problems:
        print("问题:", problems)
    print(f"风险规则命中 {len(findings)} 条: "
          + ", ".join(f.title for f in findings))
    print("事件序列:", " -> ".join(e["type"] for e in store.all_events()))
    print("报告:", report)
    store.close()


if __name__ == "__main__":
    main()
