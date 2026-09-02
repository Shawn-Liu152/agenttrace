# AgentTrace 交接文档（HANDOFF）

> 生成时间：2026-09-02（CI 9 平台全绿后）
> 用途：新会话/新窗口直接接手，无需翻阅旧对话。
> 项目：**AI Agent 取证审计工具**（零第三方依赖、纯 Python 标准库）

---

## 一、现在做到哪了（一句话状态）

**v1.1.1 已推送 GitHub（liushukai410/agenttrace，公开仓库），CI 三平台 × 3 Python 版本 9 job 全绿，GitHub Release v1.1.0 已发布。**

| 维度 | 状态 |
|---|---|
| 版本 | v1.1.1（`agenttrace/__init__.py`、`pyproject.toml` 同步） |
| 测试 | **129 tests 全绿**（`python -m unittest discover -s tests`） |
| 攻击门禁 | 5 类篡改攻击 7/7 检出（`python tests/attack_repro.py`） |
| CI | ubuntu/windows/macos × py3.9/3.11/3.13 全通过（GitHub Actions） |
| GitHub | `github.com/liushukai410/agenttrace`，18+ commits，release v1.1.0，README badges |
| 评审历程 | 六轮外部评审 5.3 → 9.4（WorkBuddy 目录有报告） |
| 代码规模 | ~17 模块 / ~6000 行 / 零第三方依赖 |

---

## 二、项目在哪 & 关键路径

```
C:\Users\19826\Desktop\AgentTrace\            ← 仓库根（git 已 init）
├── agenttrace\            ← 产品代码（17 模块）
│   ├── store.py           ← SQLite 哈希链存储（batch() 批量模式，性能 79 倍）
│   ├── chain.py           ← SHA-256 链 + verify_chain
│   ├── anchor.py          ← HMAC 锚定 + load_key_for（ENV/配置/旧路径统一解析）
│   ├── anchor_v2.py       ← Ed25519 锚定（RFC 8032 自实现，过官方向量）
│   ├── ed25519.py         ← 零依赖 Ed25519 实现
│   ├── tsa.py             ← RFC3161 时间戳（TSQ/TSR DER 编解码）
│   ├── cms.py             ← v1.1 新增：零依赖 CMS 验签（X.509/RSA-PKCS1v1.5/PKCS7）
│   ├── cli.py             ← CLI 入口（模块级 UTF-8 reconfigure！）
│   ├── analyzer.py        ← 21+ 风险规则（误报 0%、漏报 ≤1/4）
│   ├── report.py          ← HTML 时间线报告
│   ├── bundle.py          ← 证据包导出/校验
│   ├── aggregate.py       ← 跨库聚合
│   ├── adapters.py        ← OpenAI/LangGraph/Anthropic 运行时适配
│   └── schema.py / recorder.py / aggregate.py ...
├── tests\                 ← 129 tests + fixtures（tests/fixtures/*.der 已提交）
│   ├── attack_repro.py    ← 5 类攻击门禁（7/7）★CI 关键 gate
│   ├── test_cms.py        ← CMS 验签（fixture 用 cryptography 生成，需测试专用依赖）
│   ├── test_cp1252_console.py ← 跨平台编码回归（CI 血泪教训）
│   └── make_fixture.py    ← CMS fixture 生成器（懒加载 cryptography）
├── tools\benchmark.py     ← 性能基准（10 万事件 ~1.2s，85k 条/s）
├── .github\workflows\ci.yml ← 三平台 CI（★含 5 个 gate 步骤）
├── docs\interview-guide.md ← 面试讲解手册（电梯陈述→攻防→演示脚本）
├── README.md / CHANGELOG.md / SECURITY.md / CONTRIBUTING.md / LICENSE(MIT)
└── 桌面还有 AgentTrace_showcase\（一次性 demo 产物，不入库）
```

---

## 三、CI 全绿的血泪教训（新窗口必读，别再踩）

这轮从「上传 → CI 全红」到「全绿」修了 **5 轮**，根因全是平台差异：

1. **Windows 控制台 cp1252**：CLI 打印 `✔/✘/⚠/🔐` 直接 `UnicodeEncodeError` 崩。
   - 修复：`agenttrace/cli.py` **模块级** reconfigure UTF-8（放 main() 内不够——
     测试直接调 `_print_verify` 不走 main）
   - `tests/attack_repro.py`、`tools/benchmark.py` 也要各自 reconfigure
   - 回归测试：`tests/test_cp1252_console.py`（PYTHONIOENCODING=cp1252 子进程）
2. **测试内 subprocess 要显式 encoding**：`subprocess.run(..., text=True)` 在
   Windows 父进程 cp1252 下解码子进程 UTF-8 输出会崩 →
   **所有** test_*.py 的 subprocess 调用都要加 `encoding="utf-8", errors="replace"`
   （改了 6 个文件，梳理时先 `grep -rn "text=True" tests/`）
3. **CI heredoc 步骤必须 `shell: bash`**：Windows runner 默认 pwsh，`<<'EOF'` 直接炸。
   ci.yml 里所有 `run: |` + heredoc 的步骤都要加 `shell: bash`。
4. **py3.9 没有 tomllib / sys.stdlib_module_names**：pyproject 检查用
   `try: import tomllib / except: import tomli`（CI 已装 tomli 当测试依赖）；
   zero-dep 门禁用 `importlib.util.find_spec` + `sysconfig stdlib 路径`比对（别维护手工名单）。
   - 注意：os→`frozen`、time/sys→`built-in` origin 不是路径，判定要按
     "origin 不以路径开头" 放行。
5. **CI 测试要 cryptography**（fixture 生成用）：跑 unit tests 前
   `pip install cryptography tomli`（测试专用依赖，产品零依赖不变）。
   fixtures/*.der 已提交，没 cryptography 也能跑（懒加载）。

**当前 CI 已验证成功的组合**：3 OS × 3 Python = 9 jobs，每 job 5 个 gate：
unit tests(129) → attack_repro(7/7) → performance(50k <3s) → pip install smoke → pyproject/zero-dep parse。

---

## 四、常用命令

```bash
cd C:\Users\19826\Desktop\AgentTrace
python -m unittest discover -s tests          # 129 全量测试
python -m unittest discover -s tests -p test_cms.py -v   # CMS 专项
python tests/attack_repro.py                   # 5 类攻击门禁 7/7
python tools/benchmark.py --events 100000      # 性能基准
python tools/make_showcase.py                  # 生成桌面 showcase demo
python -m agenttrace init --db demo.db --agent hermes --anchor
python -m agenttrace record examples/sample_session.jsonl --db demo.db
python -m agenttrace verify --db demo.db       # exit 0 全绿
python -m agenttrace report --db demo.db --out report.html
```

## 五、GitHub 上传方式（无 gh CLI，用 GCM 缓存凭证）

```bash
TOKEN=$(printf "protocol=https\nhost=github.com\n\n" | git credential fill 2>/dev/null | grep '^password=' | cut -d= -f2-)
# 建仓库/查状态/发 release 全部 curl + Authorization: Bearer $TOKEN
# 例子：查 CI 状态
curl -s "https://api.github.com/repos/liushukai410/agenttrace/actions/runs?per_page=1" \
  -H "Authorization: Bearer $TOKEN"
# 拉 run 日志：/actions/runs/<id>/logs → zip（Windows 下用 python urllib 拉，curl 会 302 到 0 字节）
```
GitHub 账号：**liushukai410**。仓库公开，release v1.1.0 已有。

## 六、下一步建议（按价值排序）

1. **验收收尾**（最优先）：用户最初目标=简历项目，`docs/interview-guide.md` 已备好
   面试材料；演示脚本在 showcase 目录。确认用户是否要简历版本一页纸总结。
2. 如果继续开发：v1.2 候选功能：ECDSA CMS 验签扩展、OCSP/CRL 吊销检查、
   真实 Agent 运行时采集钩子 demo（接入 Hermes/Codex 实测）。
3. PyPI 发布（需用户决定是否公开上传 PyPI）。

## 七、记忆中的相关背景（已持久化）

- 用户验收标准：能进简历/面试能讲；大任务「没有重大成果不要停」
- 交付类任务直接做勿反复确认；文件交付默认给绝对路径文本
- 可视化偏好：数据/事实问题必须出图表
- AgentTrace 相关已存 memory：版本/测试数/GitHub 仓库/六轮评审 5.3→9.4