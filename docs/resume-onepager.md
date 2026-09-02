# AgentTrace — 简历一页纸（项目总结）

> 配套材料：`docs/interview-guide.md`（面试讲解稿）｜仓库 https://github.com/liushukai410/agenttrace ｜PyPI: agenttrace-forensics

## 项目定位

**零依赖 AI Agent 取证审计框架**：以执法级证据保全思路记录 AI Agent 的每一步决策（用户输入、模型回复、工具调用、工具结果、错误），用密码学保证记录事后不可篡改，并支持事故时间线回放与高危行为自动标注。区别于 LangSmith/Langfuse 等"可信者视角"的可观测工具，AgentTrace 采用**不可信者视角**——假设数据库、日志文件乃至操作者都可能被改，记录本身必须可被独立验证。纯 Python 标准库实现，产品代码零第三方依赖（AST 扫描门禁）。

## 核心工作与成果

**1. 防篡改证据链与多层外部锚定**
- 设计 SHA-256 内容哈希链（prev_hash 链式绑定）+ SQLite 拒覆盖写入，检出内容篡改/中间删除/重放/时间戳伪造
- 实现 HMAC-SHA256 链尾承诺锚定（genesis/seq_max/tip_hash/meta_hash 四元组签名），攻克"哈希链可被整链重写"的根本缺陷；进一步纯 Python 实现 RFC 8032 Ed25519 非对称锚定（过官方向量 T1–T4），验证端无需私钥、公钥绑定即可检出整库伪造
- 对接 RFC 3161 权威时间戳（TSQ/TSR 零依赖 DER 编解码，freetsa.org 实测通过），形成"存在性证明"法律级时间锚

**2. 零依赖密码学信任链（最大技术亮点）**
- 手写 DER/ASN.1 解析栈，纯标准库实现 X.509 证书解析、PKCS#7/CMS SignedData 验证（signedAttrs [1]→SET 形态重建、messageDigest 比对、签名者证书匹配、CA 链判定、genTime 有效期窗口）
- 实现 RSA PKCS#1 v1.5 与 NIST P-256 ECDSA 双算法验签（手写椭圆曲线点加/倍点/标量乘、未压缩点解码、DER r,s 解析，只验不签），按证书公钥类型自动分派；摘要算法门禁仅放行 SHA-256、算法 OID 缺失即 fail-closed，防算法混淆攻击
- 实现 CRL 本地吊销检查（签名验证、序列号命中、nextUpdate 新鲜度）与 OCSP 在线检查（请求构造与 cryptography 逐字节一致、nonce 防重放、时间窗校验、CA/委派链验签）
- **每个自实现密码学组件均与 cryptography 库交叉验证**：8 组随机 EC 密钥逐组比对、多点位篡改/错 nonce/错 issuer 全部判定一致；产品代码仍保持零依赖

**3. 真实 Agent 运行时零侵入采集**
- 框架适配器层：OpenAI Chat Completions / Responses API（含流式 delta 合并）/ LangGraph 检查点 → 统一证据事件，不 import 任何 SDK
- 运行时钩子：鸭子类型包装 OpenAI 兼容客户端与工具函数（装饰器），请求/响应/流式块自动入链，返回值与异常语义不变；修复多 Recorder 实例 seq 冲突的真实并发缺陷

**4. 风险分析与审计产出**
- 规则引擎覆盖 21+ 风险类别（危险命令/敏感路径/密钥凭证/PII/数据外发/提示注入），经评审基准迭代将误报率从 36% 降至 0、高危漏报从 80% 降至 ≤25%（三态语境判定）
- 单文件 HTML 时间线回放报告（搜索/过滤/哈希展示）、`--redact` 渲染层脱敏（证据本体不动）、跨会话聚合审计画像、证据包一体归档与清单校验

## 量化成果

| 维度 | 数据 |
|---|---|
| 代码规模 | 产品代码 4,383 行 / 19 模块（纯标准库），含测试共 ~7,100 行 |
| 测试 | **170 个单元测试全绿**：密码学交叉验证、7 类篡改攻击门禁 7/7、CLI 端到端集成、误报/漏报回归 |
| 性能 | 10 万事件批量摄入 **1.17s（85,453 条/s，较逐条提交优化 79 倍，O(n²)→O(n)）**；全链 verify ~1s |
| 工程质量 | GitHub Actions 三系统（Ubuntu/Windows/macOS）× 三 Python 版本共 **9 job 全绿**；sdist+wheel 双产物发布 PyPI |
| 迭代过程 | **六轮独立外部评审，评分 5.3 → 9.4**；攻击检出率 3/5 → 7/7 |
| 安全纪律 | SECURITY.md 已知边界表 + "降级必须显式声明"工程纪律（任何"看似有效实则未验证"的路径按漏洞处理） |

## 技术栈关键词

Python 标准库、密码学（SHA-256/HMAC/Ed25519/RSA/ECDSA P-256/X.509/PKCS#7-CMS/CRL/OCSP/RFC 3161/DER-ASN.1）、SQLite、哈希链/防篡改日志、LLM Agent 安全、OpenAI/LangGraph 适配、CI/CD（GitHub Actions 矩阵）、打包发布（setuptools/PyPI）。

## 现场可演示

① 正常库 verify 全绿 → 篡改一条事件后立即报警（对比演示）；② 零依赖 CMS 验签（RSA/ECDSA）+ CRL/OCSP 吊销拦截（吊销证书 exit 2）；③ 3 行代码包装真实 OpenAI 客户端自动入链（离线 demo 同构可跑）；④ 10 万事件秒级摄入与验证；⑤ HTML 事故时间线报告。
