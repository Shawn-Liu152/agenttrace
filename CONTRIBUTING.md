# Contributing to AgentTrace

感谢你考虑为 AgentTrace 做贡献！这是一个零依赖的取证工具，安全正确性优先于一切。

## 头号纪律：降级必须显式声明（Mandatory Degradation Disclosure）

**任何校验在保护强度不足时，输出必须与强度充足时在信号上可区分。**

这句话是三次评审（v0.1 → v1.0）反复踩坑换来的规矩，历史案例：

| 版本 | 违规表现 | 后果 |
|---|---|---|
| v0.1 | README 承诺"任何篡改都能检测"（哈希链自洽≠防篡改） | 5 类攻击 3 类穿透 |
| v0.4 | `seal verify` 无公钥绑定仍输出"✔ 验证通过" | 默认路径可伪造 |
| v0.5 | 未锚定库导出证据包静默无告警 | 接收方误以为已锚定 |
| v1.0 | `tsa verify` 对无签名伪造 TSR 说"✔ 时间戳绑定有效" | 用户以为有法律级时间证明 |

**新增任何校验/命令/输出时必须自问：**
1. 这个功能的保护强度边界是什么？
2. 边界之外，输出是否仍与边界之内**看起来一样**？
3. 如果是，就必须降级（警告/退出码/文案区分），且补测试钉住该边界。

**回归门禁**：每个"降级路径"都要有一个测试断言"降级输出存在"
（现有榜样：`test_forged_tsr_verify_ok_but_cli_flags_cms`、
`test_unbound_verify_cannot_detect_reseal`）。

## 第二条纪律：测试必须封闭（Test Isolation）

**测试绝不能读写真实用户环境。**（终评 4.2 案例：`test_c_hmac_key_deleted`
曾直接删除 `%APPDATA%\agenttrace\keys\` 下的文件——在 sandbox 里被 safe-delete
拦截暴露了不封闭，极端情况下会误删用户真实密钥。）

规则：
1. 数据库、密钥、报告一律用 `tempfile.mkdtemp()`
2. 需要换密钥位置时用环境变量（`AGENTTRACE_ANCHOR_KEY_PATH` 等）指向临时目录
3. 测试结束不留任何产物在用户目录（`%APPDATA%` / `~/.config` / 桌面）
4. 不要在测试里 `import glob` 扫用户目录

**自查**：测试跑完后检查 keys 目录/桌面/用户配置目录无新增文件。

## 开发环境

```bash
git clone <your-fork>
cd AgentTrace
python -m unittest discover -s tests -v   # 运行全部测试
```

无任何第三方依赖需要安装。支持 Python 3.9+。

## 改动守则

1. **取证语义红线**：证据库不允许覆盖/删除已有事件；新增行为不得削弱 `verify` 的检出能力。
2. **外部锚定优先**：任何"防篡改"相关改动必须考虑威胁模型（谁能接触数据库？谁能接触密钥？），并在 README 更新保护边界表。
3. **规则改动必须配测试**：风险规则的每条新增/修改正则，必须在 `tests/test_rules_quality.py` 补 FP（正常行为不误报）与 FN（威胁行为必检出）用例。
4. **零依赖保持**：核心包 `agenttrace/` 只允许标准库。新功能需要第三方库时，做成可选特性并文档化。
5. **先写攻击，再写修复**：修复安全问题时，先在 `tests/attack_repro.py` 或 `tests/test_anchor.py` 复现漏洞，再实现修复并证明测试从红转绿。

## 提交规范

```
类型: 简短描述

可选正文（说明动机与影响）
```

类型：`fix:` / `feat:` / `test:` / `docs:` / `chore:` / `refactor:`

## 质量门禁（提交前自检）

```bash
python -m unittest discover -s tests -v   # 必须全绿
python -m agenttrace verify --db <你的测试库> --anchor   # CLI 冒烟
```

新增测试时保持"每个安全声明至少一个红转绿用例"的原则。

## 需要帮助？

- 安全设计问题：开 issue 讨论威胁模型，不要直接改核心
- 规则扩充：欢迎贡献更多 FP/FN 用例或规则，必须带测试