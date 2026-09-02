"""多会话聚合（aggregate v0.7）测试：跨库画像、风险排行、异常标记、HTML/CLI。"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace.aggregate import aggregate_dbs, profile_db, render_agg_html, render_agg_text
from agenttrace.recorder import (
    Recorder, make_session_start, make_tool_call, make_tool_result, make_user_message,
)
from agenttrace.store import EvidenceStore


def build_db(path: str, agent: str, with_risk: bool = True) -> None:
    s = EvidenceStore(path)
    r = Recorder(s)
    s.set_meta("agent", agent)
    s.set_meta("model", "m")
    r.ingest(make_session_start(agent=agent, model="m", tools=["terminal"]))
    r.ingest(make_user_message("执行清理任务"))
    cmd = "rm -rf /data/old" if with_risk else "ls /data/old"
    r.ingest(make_tool_call("terminal", {"command": cmd}))
    r.ingest(make_tool_result("terminal", "done"))
    s.close()


class TestAggregate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.risky = os.path.join(self.tmp, "risky.db")
        self.clean = os.path.join(self.tmp, "clean.db")
        build_db(self.risky, agent="hermes-a", with_risk=True)
        build_db(self.clean, agent="hermes-b", with_risk=False)

    def test_profile_db_counts(self):
        p = profile_db(self.risky)
        self.assertIsNone(p["error"])
        self.assertEqual(p["event_count"], 4)
        self.assertEqual(p["finding_count"], 1)  # rm -rf 检出
        self.assertEqual(p["sev_dist"]["high"], 1)
        self.assertTrue(p["chain_ok"])

    def test_aggregate_totals_and_ranking(self):
        agg = aggregate_dbs([self.risky, self.clean])
        self.assertEqual(agg["db_count"], 2)
        self.assertEqual(agg["total_events"], 8)
        self.assertEqual(agg["total_findings"], 1)
        self.assertEqual(agg["severity" if False else "sev_dist"]["high"], 1)
        self.assertEqual(len(agg["cat_rank"]), 1)
        self.assertEqual(agg["cat_rank"][0]["category"], "dangerous_cmd")
        self.assertEqual(set(agg["agents"]), {"hermes-a", "hermes-b"})
        self.assertEqual(agg["error_dbs"], [])

    def test_error_db_reported(self):
        missing = os.path.join(self.tmp, "nope.db")
        agg = aggregate_dbs([missing, self.clean])
        self.assertEqual(agg["error_dbs"], ["nope.db"])
        self.assertEqual(agg["db_count"], 2)

    def test_render_html_contains_key_data(self):
        agg = aggregate_dbs([self.risky, self.clean])
        html = render_agg_html(agg)
        self.assertIn("AgentTrace 聚合审计", html)
        self.assertIn("hermes-a", html)
        # HTML 渲染用中文类别名（CATEGORY_NAMES 映射），非内部英文 key
        self.assertIn("危险命令", html)

    def test_render_text_summary(self):
        agg = aggregate_dbs([self.risky, self.clean])
        txt = render_agg_text(agg)
        self.assertIn("事件: 8", txt)  # 摘要头部（文本格式："事件: N"）
        self.assertIn("危险命令: 1", txt)
        self.assertIn("链OK", txt)


class TestAggregateCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.risky = os.path.join(self.tmp, "risky.db")
        self.clean = os.path.join(self.tmp, "clean.db")
        build_db(self.risky, agent="hermes-a", with_risk=True)
        build_db(self.clean, agent="hermes-b", with_risk=False)

    def test_cli_aggregate_text_and_html(self):
        out = os.path.join(self.tmp, "agg.html")
        env = {**os.environ,
               "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}
        r = subprocess.run(
            [sys.executable, "-m", "agenttrace", "aggregate",
             "--dbs", f"{self.risky},{self.clean}", "--out", out],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", cwd=self.tmp, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("聚合报告已生成", r.stdout)
        self.assertTrue(os.path.exists(out))
        with open(out, encoding="utf-8") as f:
            html = f.read()
        self.assertIn("危险命令", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)