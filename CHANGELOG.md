# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 与
[Semantic Versioning](https://semver.org/lang/zh-CN/)。

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