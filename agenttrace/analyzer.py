"""AgentTrace 风险分析：从证据链中自动标记高风险行为。

分析维度：
  1. 危险命令/操作     — rm -rf、shutdown、git push --force、format 等
  2. 敏感路径访问      — 密码文件、.env、私钥、系统目录、回收站删除
  3. 敏感信息外泄      — API key、手机号、身份证、邮箱、银行卡
  4. 凭证/密钥写入     — 写出含密钥内容的文件
  5. 数据销毁          — DROP TABLE、DELETE、清空数据库
  6. 网络外发          — 上传文件、POST 到外部域名

每条命中返回 Finding: {seq, type, severity(high/medium/low), title, detail}
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}

# ---------------------------------------------------------------------------
# 规则表
# ---------------------------------------------------------------------------

DANGEROUS_CMD_PATTERNS = [
    # (正则, 严重度, 标题)
    (r"(?i)\brm\s+(-[a-z]*\s+)*-rf\b", "high", "递归强制删除 (rm -rf)"),
    (r"(?i)\brm\s+--recursive\s+--force\b", "high", "递归强制删除 (rm --recursive --force)"),
    (r"(?i)\bdel\s+/[sfq]?\s*/[sfq]?", "high", "强制删除 (del /s /f /q)"),
    (r"(?i)\bformat\s+[a-z]:", "high", "磁盘格式化"),
    (r"(?i)\bshutdown\b", "medium", "关机/重启命令"),
    (r"(?i)\bmkfs(?:\s|\.|$)", "high", "文件系统创建 (mkfs)"),
    (r"(?i)\bdd\s+if=.*\bof=/dev/", "high", "块级写入 (dd 到设备)"),
    (r"(?i)\bgit\s+push\s+.*--force\b", "medium", "强制推送 git (force push)"),
    (r"(?i)\bgit\s+reset\s+--hard\b", "medium", "硬重置 git (reset --hard)"),
    (r"(?i)\bdrop\s+table\b", "high", "删除数据库表 (DROP TABLE)"),
    (r"(?i)\btruncate\s+table\b", "medium", "清空数据库表 (TRUNCATE)"),
    (r"(?i)\bdelete\s+from\b", "low", "数据库删除语句 (DELETE FROM)"),
    (r"(?i)\breg\s+delete\b", "medium", "删除注册表项"),
    (r"(?i)\bcipher\s+/w:", "medium", "擦除磁盘可用空间"),
    (r"(?i)\bdiskpart\b", "medium", "磁盘分区工具"),
    (r"(?i)\bsudo\s+su\s*-", "high", "切换到 root (sudo su)"),
    (r"(?i)\biptables\s+-F\b", "medium", "清空防火墙规则 (iptables -F)"),
    (r"(?i)\bkubectl\s+delete\s+namespace\b", "high", "删除 K8s 命名空间"),
    (r"(?i)\bnetsh\s+firewall\s+delete\b", "medium", "删除防火墙规则"),
]

SENSITIVE_PATH_PATTERNS = [
    (r"(?i)(/etc/passwd|/etc/shadow|/etc/sudoers)", "high", "系统密码文件"),
    (r"(?i)\.env\b", "medium", "环境变量/密钥文件 (.env)"),
    (r"(?i)(id_rsa|id_ed25519|\.pem\b|\.key\b)", "high", "私钥文件"),
    (r"(?i)(password|passwd|secret|token|api[_-]?key)\.(txt|json|log|bak|db)", "medium", "疑似密钥存储文件"),
    # 系统二进制目录检测由 _scan_system_bin 独立处理（见下，排除用户路径）
    (r"(?i)(C:\\Windows\\System32[/\\])", "medium", "Windows 系统目录"),
    (r"(?i)\.git/config\b", "low", "git 配置"),
    (r"(?i)(cookies\.sqlite|login\.db|key[34]?\.db)", "high", "浏览器/应用凭据库"),
]

SECRET_PATTERNS = [
    # OpenAI/anthropic/其他 sk- 格式
    (r"\bsk-[A-Za-z0-9_-]{16,}\b", "high", "API Key (sk-...)"),
    # 通用 64 位 hex：必须紧跟密钥语境才报（避免 git 提交/哈希误报）
    (r"(?i)(\b(?:key|token|secret|passwd|password|api[_-]?key|bearer)\b[^\n]{0,20}?)[0-9a-fA-F]{32,}", "medium", "疑似密钥串 (hex)"),
    (r"(?i)(github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{30,})", "high", "GitHub Token"),
    (r"(?i)(AKIA[0-9A-Z]{16})", "high", "AWS Access Key"),
    (r"(?i)(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)", "high", "PEM 私钥内容"),
]

PII_PATTERNS = [
    (r"\b1[3-9]\d{9}\b", "medium", "手机号"),
    (r"\b\d{17}[\dXx]\b", "medium", "身份证号"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "medium", "银行卡号"),
]

EXFIL_NET_CMDS = [
    (r"(?i)\b(curl|wget|powershell|Invoke-WebRequest)\b.*\b(-T|--upload-file|upload|post)", "medium", "疑似文件上传命令"),
    (r"(?i)\bscp\s+\S+.*:", "medium", "SCP 远程拷贝"),
    (r"(?i)\bnetcat|nc\s+-[a-z]*[e]", "high", "Netcat 反弹/外传"),
    (r"(?i)base64\b[^\n|]*\|\s*(curl|wget)\b", "high", "base64 编码后外传"),
    (r"(?i)(curl|wget)\b[^\n]*\b-d\s+@-", "medium", "stdin 数据外传 (curl -d @-)"),
    (r"(?i)requests\.(post|put)\b[^\n]*files=", "high", "Python 上传文件 (requests files=)"),
]

# 提示注入检测：纳入 user_message 扫描
PROMPT_INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?previous\s+(instructions|prompts|messages)", "high", "提示注入 (忽略前文指令)"),
    (r"(?i)ignore\s+the\s+above", "high", "提示注入 (忽略上文)"),
    (r"(?i)(disregard|forget)\s+(all\s+)?(prior|previous)\s+instructions", "high", "提示注入 (弃置指令)"),
    (r"(?i)忽略(之前|以上|先前)(的)?(所有)?(指令|指示|提示)", "high", "提示注入 (中文变体)"),
]

# 组合规则：不同类型分别报告时用的类别名
CATEGORY_NAMES = {
    "dangerous_cmd": "危险命令",
    "sensitive_path": "敏感路径",
    "secret": "密钥/凭证",
    "pii": "个人信息",
    "exfil": "数据外发",
    "prompt_injection": "提示注入",
}


class Finding:
    def __init__(self, seq: int, category: str, severity: str, title: str, detail: str):
        self.seq = seq
        self.category = category
        self.category_name = CATEGORY_NAMES.get(category, category)
        self.severity = severity
        self.title = title
        self.detail = detail

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "category": self.category,
            "category_name": CATEGORY_NAMES.get(self.category, self.category),
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }


def _text_of(ev: Dict[str, Any]) -> str:
    """把事件内容展平成可扫描文本。"""
    parts = []
    cont = ev.get("content")
    if isinstance(cont, str):
        parts.append(cont)
    elif isinstance(cont, dict):
        # 工具调用常有 name/arguments/command 字段
        for key in ("name", "tool", "command", "arguments", "input", "query", "url", "path", "stdout", "stderr", "result", "error"):
            v = cont.get(key)
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, (dict, list)):
                parts.append(json.dumps(v, ensure_ascii=False))
        # 兜底全量
        parts.append(json.dumps(cont, ensure_ascii=False))
    elif isinstance(cont, list):
        parts.append(json.dumps(cont, ensure_ascii=False))
    return "\n".join(parts)


def _scan(text: str, patterns: List[tuple]) -> List[tuple]:
    hits = []
    for pat, sev, title in patterns:
        m = re.search(pat, text)
        if m:
            snippet = text[max(0, m.start() - 30): m.end() + 30].replace("\n", " ")
            hits.append((sev, title, snippet))
    return hits


# 系统目录检测的排除前缀（用户路径不误报）
_USER_PATH_PREFIXES = ("/home/", "~/", "/user", "/Users/", "C:\\Users\\", "c:/users/")
# 系统目录风险只在写操作命令语境下报（rm/del/mv/chmod/dd 等），
# 正常执行（python3/ls/find/cat）不报 —— 避免“/usr/bin/python3”这类误报
_SYSTEM_BIN_RISKY_VERBS = (
    "rm", "del", "erase", "mv", "chmod", "chown", "dd", "shred",
    "wipe", "overwrite", "truncate", "unlink",
)


def _scan_system_bin(text: str) -> List[tuple]:
    """检测系统二进制目录上的写操作，排除用户路径与正常执行。"""
    hits = []
    has_risky_verb = re.search(r"(?i)\b(" + "|".join(_SYSTEM_BIN_RISKY_VERBS) + r")\b", text)
    if not has_risky_verb:
        return hits
    for m in re.finditer(r"(?i)[/\\](?:usr[/\\])?bin[/\\]", text):
        prefix = text[max(0, m.start() - 40): m.start()]
        if any(p.lower() in prefix.lower() for p in _USER_PATH_PREFIXES):
            continue
        snippet = text[max(0, m.start() - 30): m.end() + 30].replace("\n", " ")
        hits.append(("medium", "系统二进制目录写操作", snippet))
        break  # 每条事件报一次即可
    return hits


def analyze_event(ev: Dict[str, Any]) -> List[Finding]:
    """分析单条事件，返回命中列表。"""
    if ev.get("type") not in ("tool_call", "tool_result", "agent_message", "error", "user_message"):
        return []
    findings: List[Finding] = []
    seq = ev.get("seq", "?")
    text = _text_of(ev)

    checks = [
        ("dangerous_cmd", DANGEROUS_CMD_PATTERNS),
        ("sensitive_path", SENSITIVE_PATH_PATTERNS),
        ("secret", SECRET_PATTERNS),
        ("pii", PII_PATTERNS),
        ("exfil", EXFIL_NET_CMDS),
    ]
    # user_message 额外扫描提示注入
    if ev.get("type") == "user_message":
        checks.append(("prompt_injection", PROMPT_INJECTION_PATTERNS))
    for category, patterns in checks:
        for sev, title, snippet in _scan(text, patterns):
            findings.append(Finding(seq, category, sev, title, snippet))
    # 系统二进制目录：独立逻辑（排除用户路径误报）
    for sev, title, snippet in _scan_system_bin(text):
        findings.append(Finding(seq, "sensitive_path", sev, title, snippet))
    return findings


def analyze_chain(events: List[Dict[str, Any]]) -> List[Finding]:
    """分析整条证据链，按严重度排序返回全部发现。"""
    findings: List[Finding] = []
    for ev in events:
        findings.extend(analyze_event(ev))
    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.seq), reverse=True
    )
    return findings


def summarize(findings: List[Finding]) -> Dict[str, Any]:
    """汇总统计。"""
    by_sev = {"high": 0, "medium": 0, "low": 0}
    by_cat: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_category": by_cat,
    }