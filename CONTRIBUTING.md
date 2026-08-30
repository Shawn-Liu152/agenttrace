# Contributing to AgentTrace

感谢你考虑为 AgentTrace 做贡献！这是一个零依赖的取证工具，安全正确性优先于一切。

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