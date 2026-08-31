"""
AgentTrace — AI Agent 取证审计工具
===================================

记录 AI Agent 的每一步决策（用户输入、模型回复、工具调用、工具结果、
错误），构建防篡改的证据链（SHA-256 哈希链），支持风险分析（危险命令、
敏感路径、PII 外泄）与 HTML 时间线回放审计报告。

零第三方依赖：纯 Python 标准库。

用法:
    agenttrace record session.jsonl --db evidence.db
    agenttrace verify --db evidence.db
    agenttrace analyze --db evidence.db
    agenttrace report --db evidence.db --out report.html
"""

__version__ = "1.0.1"