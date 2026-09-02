# Security Policy

AgentTrace 是一个取证/审计工具——它存在的前提就是**可信**。安全漏洞在这里
不只是 bug，而是可能让使用者误信伪造证据的东西。

## 支持的版本

| 版本 | 安全支持 |
|---|---|
| 1.2.x | ✅ 当前版本，积极维护 |
| 1.0.x – 1.1.x | ✅ 维护（修订记录见 CHANGELOG） |
| 0.x | ❌ 已停止（修订记录见 CHANGELOG） |

## 报告漏洞（Reporting a Vulnerability）

**请勿公开披露**。发现安全问题请：

1. 撰写报告，包含：
   - 影响版本 / 复现步骤（尽量最小化）
   - 影响面（能否伪造证据 / 绕过校验 / 破坏链完整性）
   - 建议修复方向（如果有）
2. 通过 GitHub Issues **标记 `security`** 或直接联系维护者
   （私人安全仓库 / 邮箱见仓库主页）。
3. 预期流程：
   - 48h 内确认收到
   - 7 天内给出评估（漏洞等级与修复计划）
   - 修复后共同商定公开披露时间（默认 30 天）

## 已知安全边界（不是漏洞，是设计边界）

本项目坚持**零第三方依赖**，因此以下边界必须知悉：

| 边界 | 说明 | 缓解 |
|---|---|---|
| **HMAC 锚定密钥与库同获** | 攻击者同时拿到密钥文件与库可重签 | 密钥默认在用户配置目录；生产用环境变量/离线保管 |
| **Ed25519 私钥泄露** | 拿到私钥可重签锚定 | 私钥只留签名端，验证端只用公钥绑定（`--public-key`） |
| **TSA CMS 签名（无 --cafile）** | 无 CA 时只校验 messageImprint 绑定 | CLI 输出强制声明 + `--cafile` 零依赖验签（v1.1+）/openssl 指引 |
| **CMS 验签算法范围（有 --cafile）** | 仅 sha256WithRSA 与 ecdsa-with-SHA256(P-256)；摘要仅 SHA-256；其余曲线/算法不支持 | 算法 OID 缺失即 fail-closed（防算法混淆），其余算法显式报"不支持"，绝不静默通过 |
| **ECDSA P-256 实现（`ecc.py`）** | 只验不签；仿射坐标实现非常数时间；不支持 P-384/P-521/secp256k1 | 与 cryptography 库随机密钥交叉验证一致；威胁模型是事后验证 TSR，不抗时序攻击 |
| **CRL 吊销检查（`--crl-file`）** | 不联网、只校验调用方提供的 CRL；nextUpdate 过期只警告不阻断（避免拒绝服务） | stale 显式 ⚠；CRL 签名必须由受信 CA 验证通过，无 CA 时显式降级 |
| **OCSP（`--ocsp-url`）** | CertID 仅 SHA-1（RFC 6960 强制）；委派响应者只验证"证书链到受信 CA"，不做 EKU/OCSP-signing 深度校验；响应者 ID 不参与信任决策（直接试 CA 公钥验签） | nonce 防重放、thisUpdate/nextUpdate 时间窗校验、non-successful 状态拒绝 |
| **纯 Python 密码学常时性** | `ed25519.py`/`ecc.py` 标量乘非常数时间 | 威胁模型是事后篡改检测；高对抗场景换 libsodium/`cryptography` 后端 |
| **后端信任** | TSA/OCSP 响应源本身的诚实性 | 用权威 TSA/OCSP + 受信 CA 锚 + openssl 交叉验证 |

**降级纪律**：任何校验在保护强度不足时必须显式声明（见 CONTRIBUTING
"头号纪律"）——如果发现某路径输出"看起来有效"但实际未验证，这是漏洞，
请立即报告。

## 安全相关测试

- `tests/attack_repro.py` — 评审 7 类篡改攻击门禁
- `tests/test_tsa.py::TestForgedTsrFlagged` — 伪造时间戳不沉默
- `tests/test_verify_dispatch.py` — 锚定体系分派（误报/漏报双禁）
- `tests/test_ed25519_anchor.py` — Ed25519 攻击矩阵（RFC 8032 官方向量）
- `tests/test_cms.py::TestEcdsaCrossCheck` — ECDSA 与 cryptography 随机密钥交叉一致
- `tests/test_revocation.py` — CRL 多点位篡改/错 CA/陈旧、OCSP 错 nonce/错
  issuer/non-successful/未来时间窗、CLI 吊销 exit 2
- `tests/test_instrument.py` — 运行时钩子异常不吞、返回值原样、采集失败不阻断业务

CI 三平台全量运行，任何提交不通过即失败。