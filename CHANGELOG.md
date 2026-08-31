# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 与
[Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-08-31

### 发布里程碑：性能、真实 TSA、打包、多平台 CI

- **性能优化 79 倍**：`EvidenceStore.batch()` 批量模式（延迟 commit +
  链尾缓存 + 锚定合并更新，O(n²) → O(n)）——10 万事件追加从 92.5s
  降到 **1.17s（85,453 条/s）**；verify 10 万条 ~1s；新增
  `tests/test_batch.py`（5 用例）+ `tools/benchmark.py` 性能门禁
- **真实 TSA 打通**：`tsa.py` TSTInfo 定位改为按 `id-ct-TSTInfo` OID
  锚点解析（真实 TSR 的 TSTInfo 被 CMS 包在 OCTET STRING 内，盲扫会
  误中签名区）——公共 freetsa.org 实测 **granted + genTime + 哈希绑定
  全部正确**；mock TSR 同步升级为真实 CMS SignedData 结构
- **Anthropic 适配器**：`ingest_anthropic_messages()`——tool_use /
  tool_result content blocks 转换（tool_call_id 入 content），
  `tests/test_adapters.py` +2 用例
- **打包发布验证**：pip wheel 构建 + 隔离 venv 安装 +
  `agenttrace` console 入口冒烟（init/record/verify/analyze 全链路）
- **CI 三平台矩阵**：ubuntu/windows/macos × Python 3.9/3.11/3.13；
  新增性能回归门禁（5 万事件 <3s）与打包安装冒烟 job
- 全量 **111 测试**（103 + batch 5 + adapters 2 + tsa 结构重构回归）

## [0.9.0] - 2026-08-31

### RFC3161 时间戳锚定（路线图收官项：tsa）

- **新增 `agenttrace/tsa.py`**——对接权威 TSA 打"存在性证明"时间戳，
  零第三方依赖（手写最小 DER/ASN.1 编解码）：
  - `build_tsq()` 构造 RFC3161 TimeStampReq（version/messageImprint/nonce）
  - `parse_tsr()` 解析 TimeStampResp：status、genTime、messageImprint
    回显哈希（深度优先 DER 扫描，兼容 CMS ContentInfo 嵌套结构）
  - `request_timestamp()` 用 urllib POST（application/timestamp-query）
  - `stamp()` 把 TSQ/TSR/解析摘要写入 `<db>.anchor.tsq/.tsr/.tsa.json`
  - `verify()` 校验 messageImprint 双向绑定——TSA 签署的确实是
    **这份锚定内容**；篡改锚定或替换 TSR 都会检出（exit 2）
- **CLI**：`tsa stamp --db ev.db [--tsa-url https://freetsa.org/tsr]` /
  `tsa verify --db ev.db`
- **诚实边界（README 已声明）**：不验证 TSR 内 CMS 签名的合法性
  （需 X.509/CA 链校验，超出零依赖范围）——生产/执法场景用
  `openssl ts -verify -data <tsq> -in <tsr> -CAfile <tsa_cert.pem>` 验签；
  网络不可达时明确报错不伪造成功
- 新增 `tests/test_tsa.py`（9 用例：DER 往返 / TSQ 结构 / mock TSA
  stamp-verify / 篡改锚定检出 / 替换 TSR 检出 / 拒绝状态 / 文件缺失 /
  genTime）；全量 **102 测试**

## [0.8.0] - 2026-08-31

### Agent 框架适配器（路线图项：真实运行时取证钩子）

- **新增 `agenttrace/adapters.py`**——把主流 Agent 框架的运行时数据转成
  AgentTrace 事件，**保持零第三方依赖**（不 import openai/langgraph，
  纯 dict 转换，SDK 集成由用户 3 行接入）：
  - `ingest_messages()`：统一 OpenAI Chat Completions 消息数组
    （role: user/assistant/tool + tool_calls）与 LangGraph 消息
    （type: human/ai/tool/system + tool_calls/args）
  - `ingest_openai_response_events()`：Responses API **流式事件**摄入——
    文本 delta 合并为一条 agent_message、function_call_arguments.delta
    合并为一条 tool_call、function_call_output → tool_result，未知事件
    静默跳过不打断采集
  - `ingest_langgraph_state()`：LangGraph 检查点 messages 直接摄入
- 工具调用 ID（tool_call_id）写入事件 content（store 表无顶层列，
  保证入库）；自动补 session_start（meta 记 agent/model），重复摄入不
  重复建会话
- 新增 `tests/test_adapters.py`（6 用例）+ `examples/adapter_demo.py`
  （两种格式 + 链验证 + 风险检出 + 报告全流程示例）；全量 93 测试

## [0.7.0] - 2026-08-31

### 多会话聚合审计（路线图项：aggregate）

- **新命令 `aggregate`**：`--dbs a.db,b.db [--out agg.html]` —— 跨证据库
  审计画像，取证场景天然单元是"一个库 = 一次会话/一个事故"
- 每库画像：事件数 / 类型分布 / agent / model / 时间跨度 / 风险发现
  （严重度分布 + 类别分布）/ 链验证状态 / 锚定状态；不存在的库或空库
  独立标记 error 不中断整体
- 全局画像：总事件 / 总风险 / 风险类别排行 / Agent 数 / 高危事件 Top
- 输出：终端文本摘要 + 可选 HTML 聚合报告（复用暗色视觉语言）
- 新增 `agenttrace/aggregate.py` + `tests/test_aggregate.py`（6 用例：
  单库画像 / 聚合统计与排行 / error 库 / HTML / 文本 / CLI 端到端）；
  全量 87 测试

## [0.6.0] - 2026-08-30

### 报告脱敏（路线图项：--redact）

- **`report --redact`**：报告中的密钥（sk-/ghp_/AKIA/PEM/hex 密钥语境/bearer）
  与 PII（手机号/身份证/银行卡）打码——保留首 4 尾 2 字符便于定位，
  短串全遮；`bundle export --redact` 同样生效（证据库/锚定本体不变）
- **渲染层脱敏设计**：打码只作用于展示文本，证据库原始内容保持原样
  （证据是链上事实，篡改它才是犯罪）——测试固定该边界
- 复用 analyzer 的 secret/pii 正则作为单一事实来源，新增
  `redact_text()` / `_redact_event()` / `_redact_finding()`
- 新增 `tests/test_redact.py`（11 用例：打码/保留定位/不误伤短串/
  正常文本不变/证据库不动/HTML 无泄漏）；全量 81 测试

## [0.5.0] - 2026-08-30

### 证据包导出（路线图项：证据包归档）

- **新命令 `bundle`**：
  - `bundle export --db ev.db [--out xxx.zip]` —— 一次打包全部证据：
    证据库 + 外部锚定 + Ed25519 公钥（`anchor.public_key.txt`，从锚定记录
    内嵌公钥生成）+ 最新审计报告 + `manifest.json`（每文件 SHA-256）
    + 验证者 README（逐步验证指引）
  - `bundle verify-manifest <解包目录>` —— 包清单校验：逐文件哈希比对 +
    缺失文件检出 + **未登记新增文件检出**
- **包内规范名**：无论源库名，包内统一 `evidence.db` / `evidence.db.anchor.json`
  ——与 README 指引一致，防止验证者误指路径被 sqlite 静默建空库误导
- **接收方独立验证**（无需签名私钥 / 无需 HMAC 密钥）：
  `verify-manifest` → `seal verify --public-key <包内公钥，经独立渠道核对>`
- 新增 `agenttrace/bundle.py` + `tests/test_bundle.py`（8 用例：
  成员完整 / 清单通过 / 篡改检出 / 新增文件检出 / 缺失检出 / 解包库独立验证 /
  空库拒绝 / HMAC-only 包降级验证）；全量 70 测试
- 已知边界：manifest 自身不签名——防"包内单文件被替换"；整包伪造的防线
  在锚定签名 + 公钥独立渠道核对（README.txt 已说明）

## [0.4.1] - 2026-08-30

### 复评 P1：默认验证路径诚实化（三条建议全部落实）

- **`seal verify` 无 `--public-key` 时输出降级警告**（与未锚定警告对齐）：
  「⚠ 未绑定期望公钥：本验证只能证明锚定自洽，无法排除"攻击者自造密钥重签"」，
  成功文案改为「锚定自洽（仅自洽校验，非防伪造证明）」，退出码保持 0
- **测试名修正**：`test_attack_wrong_keypair_detected` →
  `..._when_pubkey_bound`；新增 `test_unbound_verify_cannot_detect_reseal`
  把"不绑定时无法检出"的边界用测试固定（将来改默认行为 CI 会提醒权衡）
- **README**：`--public-key` 从"合规/对抗场景"提升为**默认推荐步骤**；
  新增 Ed25519 已知密码学边界（非常数时间标量乘 / cofactorless 验证）
- 代码卫生：`anchor.py` docstring raw-string 消除 SyntaxWarning；
  `anchor_v2.py`/测试 `json.load(open(...))` 改 with 消除 ResourceWarning
- 62 测试全绿（+1 边界测试），`-W error::ResourceWarning/SyntaxWarning` 干净

## [0.4.0] - 2026-08-30

### Ed25519 非对称锚定（复评 4.1 的根本解法）

- **纯 Python Ed25519（RFC 8032）**：零依赖数字签名（SHA-512 + Edwards25519），
  RFC 官方向量 T1-T4 全过，防篡改/防malleability 完整
- **新命令 `seal`**：`seal keygen` / `seal seal` / `seal verify`——私钥只在签名端
  （Agent 侧，用户配置目录，与库分离），公钥内嵌锚定文件、可自由分发
- **验证端无私钥验证**：解决 HMAC"验证者必须持有签名密钥"的固有矛盾——
  验证端被攻破也只能"验证"，无法伪造锚定
- **`--public-key` 绑定**：verify 可传入可信渠道获得的期望公钥；锚定内嵌公钥
  与其不符 = 整库伪造信号（攻击者重算链+自签也会被检出）
- **meta 为空提示**（复评建议）：verify 对"meta 表为空但事件链非空"给出补录建议
- 新增 `anchor_v2.py` + `ed25519.py` + `tests/test_ed25519_anchor.py`（10 用例）
- 全部 61 测试通过

### 已知边界（诚实声明）

- `seal verify` 不带 `--public-key` 时只验证"签名与锚定内容自洽"——
  攻击者若同时持有签名端私钥可以重签。**合规/对抗场景必须通过可信渠道
  分发公钥并在验证时绑定**（`--public-key`）。

## [0.3.0] - 2026-08-30

### 安全加固（复评 4.1 / 4.2）

- **密钥默认路径迁移**：锚定密钥从 `<db>.anchor.key`（与数据库同目录）改为
  用户配置目录（Windows `%APPDATA%\agenttrace\keys\`，POSIX `~/.config/agenttrace/keys/`），
  按 db 路径哈希命名——修复"拿到库写权限者同时拿到密钥"的默认配置缺陷
- **旧位置自动回退**：`resolve_key_path()` 优先新位置，旧位置存在则自动回退
  （迁移兼容），`verify` 对旧位置密钥输出迁移建议
- **强攻击信号分级**：`verify` 现在区分「锚定文件存在 + 密钥缺失」＝疑似人为破坏，
  输出明确告警并返回退出码 2（此前混同为"未锚定"警告退出码 1）
- 新增 `anchor_state()` 统一状态探测（环境变量 / 显式路径 / 配置目录 / 旧位置）

### 测试

- 新增 `tests/test_key_placement.py`：密钥放置策略 + 强信号检测（6 用例）
- 全部 51 个测试通过（Python 3.9–3.13）

## [0.2.0] - 2026-08-30

### 安全修复（首轮评审 P0/P1 全部）

- **外部锚定**：HMAC-SHA256 链尾承诺（genesis/seq_max/tip_hash/meta_hash 签名，
  独立锚定文件 + 原子写 + `compare_digest`）——堵住末尾截断、整链重算、
  元信息篡改三类攻击（攻击检出率 2/5 → 5/5）
- **拒覆盖**：`INSERT OR REPLACE` → `INSERT` + 冲突报错（取证库禁止覆盖）
- **风险规则质量**：误报 36% → 0%（14 用例全过）；对抗漏报 80% → 30%
  （新增 `rm --recursive --force`、base64 外传、requests files= 外传、
  `sudo su`、kubectl delete namespace、iptables -F、提示注入中英文变体）
- **README 诚实化**：删掉"任何事后篡改都无法逃脱检测"错误承诺，
  新增威胁模型边界表 + 未锚定警告语
- **开源就绪**：LICENSE (MIT)、pyproject.toml、.gitignore、git 仓库

## [0.1.0] - 2026-08-30

### 初始版本

- SHA-256 哈希链证据链（内容篡改 / 中间删除 / 重放 / 时间戳检测）
- SQLite 单文件证据库 + JSONL 批量 / stdin 实时流采集
- 风险分析（5 类规则）
- HTML 时间线回放报告（搜索 / 过滤 / 哈希展示）
- 23 个单元测试