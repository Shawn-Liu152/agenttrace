# AgentTrace — 面试讲解手册（Interview Guide）

> 用途：简历作品集的配套讲解稿。按"30 秒电梯陈述 → 3 分钟深讲 → 追问攻防"
> 三层组织。所有数字均为实测数据，可现场演示验证。

---

## 一、30 秒电梯陈述

**一句话**：我给"AI Agent 的行为记录"做了个取证工具——像执法部门的证据
保全一样，用密码学保证 Agent 的每一步操作记录事后无法被篡改，并能在
事故后回放完整时间线、自动标出高危动作。

**为什么新鲜**：市面上做 Agent 监控/可观测的工具很多（LangSmith、Langfuse、
Helicone），但它们都是**可信者视角**——假设平台自己可信。AgentTrace 做的是
**不可信者视角**：假设数据库、日志文件、乃至操作者都可能被改，用
SHA-256 哈希链 + 外部锚定 + RFC3161 可信时间戳，让"记录本身"可被独立验证。

**量化成果**：零第三方依赖、~6,000 行纯 Python、126 个测试、六轮独立外部
评审从 5.3 分修到 9.4 分、10 万事件 1.17 秒摄入、三平台 CI。

---

## 二、3 分钟深讲（故事线）

### 1. 核心问题：哈希链 ≠ 防篡改

我最初的原型用的是教科书式 SHA-256 哈希链（每条事件哈希 = H(上条哈希 + 内容)）。
评审立刻揭穿：**哈希链只能证明"内部自洽"，不能证明"没被整体重写"**——
攻击者只要有写权限，读全部事件 → 改 → 从 seq 0 重算整条链 → 回写，
verify 数学上完美通过。

5 类实弹篡改攻击复现，3 类完全穿透。这是整个项目最重要的一课：
**单纯依赖密码学原语自洽性 = 虚假安全感**。

### 2. 修复：外部锚定（external anchoring）

- **HMAC 锚定**：链尾承诺 `(genesis, seq_max, tip_hash, meta_hash)` 用独立密钥
  签 MAC，密钥存在用户配置目录（与库分离）。
- **Ed25519 锚定**（自己实现 RFC 8032，过官方向量 T1/T2）：私钥只留签名端，
  验证端只用公钥——攻击者即使拿到整个数据库也补不了锚定。
- **RFC3161 时间戳**：把锚定哈希交给权威 TSA（freetsa.org）打存在性证明，
  genTime 成为"此时此哈希已存在"的法律级证据。

### 3. 诚实边界——被评审反复训练出来的纪律

评审最有价值的产出是发现了"沉默虚假信心"模式：功能降级时输出却像完整通过。
我最终把它固化成项目纪律：
- **降级必须显式声明**：`tsa verify` 无 CA 时成功输出必然伴随
  `⚠ 未验证 TSA 的 CMS 签名`；多方案 verify 按锚定算法分派，绝不误报。
- **测试封闭性**：测试不碰真实用户目录（曾因测试删 `%APPDATA%` 密钥被评审抓包）。

### 4. 零依赖密码学栈

不装 cryptography/openssl，纯标准库实现了：SHA-256、Ed25519（RFC 8032）、
RSA PKCS#1 v1.5 验签、X.509 证书解析、PKCS#7/CMS SignedData 解析、DER/ASN.1
编解码。这保证了审计工具的供应链安全——**审计者自己的依赖不能被审计**。

### 5. 工程化

126 测试（含 5 类攻击门禁 7/7、误报/漏报基准测试、篡改检出回归）、
三平台 CI（ubuntu/windows/macos × py3.9/3.11/3.13）、性能门禁
（10 万事件 <2s）、sdist/wheel 打包验证、SECURITY.md 漏洞报告渠道。

---

## 三、追问攻防（面试官可能的深挖）

### Q1: 哈希链被整体重写的防御是什么？
**锚定分离 + 时间戳**。HMAC 密钥/Ed25519 私钥/公钥都不在库附近；TSA 时间戳
证明"这个哈希在某个时间点已存在"——整体重写会产生新哈希，与既有时间戳
矛盾。诚实边界：若攻击者同时拿到密钥，锚定可被重签（这是信任模型本性，
任何取证工具都如此），缓解靠操作纪律（密钥离线保管、公钥带外分发）。

### Q2: 为什么不用现成密码学库？
审计工具的审计者必须无依赖——装了 cryptography 的取证工具，其可信性依赖
"cryptography 发布商没被攻破"。零依赖 + 官方向量交叉验证 = 供应链自证。

### Q3: 误报/漏报怎么平衡的？
规则引擎有 21+ 风险类别（危险命令/密钥泄露/提示注入等）。评审基准测试：
修复前误报率 36%（把 `/usr/bin/python3` 当密钥路径）、高危漏报 80%
（rm -rf / 只报 1/5）。修复后误报 0%、漏报 ≤1/4——为此给规则加了三态
（命令字符串/副作用/外部发信）判定。

### Q4: 时间戳 CMS 验签怎么做的？
v1.0.1 前只校验 messageImprint 绑定（哈希回显），明确声明不验 CMS 签名。
v1.1.0 用纯 Python 实现了完整验证链：X.509 解析 + RSA PKCS#1 v1.5 验签 +
signedAttrs [1]→SET 重建 + messageDigest 比对 + IssuerAndSerialNumber 匹配
签名者证书 + CA 链/self-signed 判定 + genTime 有效期窗口。与 cryptography
库交叉验证判定完全一致；无 CA 时拒绝给 "verified"（防自签伪造冒充）。

### Q5: 这项目最难的技术点？
SHA-256 链 + HMAC 锚定 + 时间戳的**验证矩阵**：任何篡改路径（末尾截断、
整链重算、元信息改、重放覆盖、密钥删/换）都要有明确输出和对的退出码，
且不能误伤合法路径（HMAC→Ed25519 迁移后 verify 不能误报"破坏"）。
为此做了跨命令端到端测试覆盖三条路径 + 强信号保留测试。

### Q6: 性能？
batch 批量模式：10 万事件摄入 1.17s（~85k 条/s，比逐条 commit 快 79 倍），
verify 1s 内，风险扫描 ~5.6s，DB 21.8MB。性能门禁在 CI 里防止回退。

---

## 四、现场演示脚本（5 分钟版）

```bash
cd C:\Users\19826\Desktop\AgentTrace_showcase   # 或仓库根

# 1. 初始化 + 摄入示例事故（含 rm -rf /、读 .env、外发密钥）
python -m agenttrace init --db demo.db --agent hermes --model gpt --anchor
python -m agenttrace record examples/sample_session.jsonl --db demo.db

# 2. 完整验证（链 + HMAC 锚定）
python -m agenttrace verify --db demo.db            # → exit 0 全绿

# 3. 篡改一条 → 立即检出
python -c "import sqlite3; c=sqlite3.connect('demo.db'); \
c.execute(\"UPDATE events SET content='{}' WHERE seq=5\"); c.commit()"
python -m agenttrace verify --db demo.db            # → exit 2 报警

# 4. 时间戳锚定（真实 freetsa.org）
python -m agenttrace tsa stamp --db demo.db         # granted + genTime
python -m agenttrace tsa verify --db demo.db --cafile tsa-ca.pem  # CMS 验签

# 5. 报告：HTML 时间线 + 风险标注 + 脱敏版
python -m agenttrace report --db demo.db --out report.html
```

**演示要点**：第 2→3 步对比是全场记忆点——"改一条，报警"。

---

## 五、简历写法建议

- **项目名称**：AgentTrace — 零依赖 AI Agent 取证审计框架
- **一句话**：为 AI Agent 构建防篡改证据链（SHA-256 链 + HMAC/Ed25519 外部
  锚定 + RFC3161 时间戳 + 纯 Python CMS 验签），六轮外部评审 5.3→9.4。
- **要点**：纯标准库实现密码学栈 / 126 测试 / 三平台 CI / 性能 79 倍优化 /
  评审驱动迭代（攻击检出率 3/5→7/7）/ 可 pip 发布
- **仓库**：https://github.com/liushukai410/agenttrace

---

*数据来源：README.md + CHANGELOG.md + 六轮评审报告（WorkBuddy\2026-08-30-17-20-30\）。*