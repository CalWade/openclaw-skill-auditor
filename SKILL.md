---
name: openclaw-skill-auditor
description: Audit installed OpenClaw skills for security risks, token bloat, and hidden cost patterns. Use this skill whenever the user asks to scan, audit, check, or review their installed skills — including questions like "are my skills safe?", "which skills are wasting tokens?", "do I have any suspicious skills?", "clean up my skills", or "check my OpenClaw skills". Always invoke this skill for any skill health, quality, or cost investigation.
---

# OpenClaw Skill Auditor

Scan all installed OpenClaw skills and surface every risk item found. No scoring — just direct warnings about what was found and where.

## Overview

The auditor runs `scripts/scan.py`, which automatically discovers and scans **all** OpenClaw skill directories:

1. `<workspace>/skills` — workspace-level skills (workspace path read from `~/.openclaw/openclaw.json` if configured)
2. `~/.openclaw/skills` — user-managed skills
3. `~/.agents/skills` — legacy path used by the `npx skills` CLI

Skills with the same name across multiple paths are deduplicated (first occurrence wins, matching OpenClaw priority order). The script writes a JSON report; you then render it as a clean terminal report and offer a delete menu.

## Workflow

### Step 1: Run the scanner

```bash
python3 ~/.openclaw/skills/openclaw-skill-auditor/scripts/scan.py \
  --out /tmp/openclaw-audit.json
```

If the user wants to include an additional path: append `--extra-root /path/to/skills`.

### Step 2: Read the JSON report

```json
{
  "scanned_at": "...",
  "roots": ["..."],
  "skill_count": 31,
  "flagged_count": 7,
  "clean_count": 24,
  "flagged": [
    {
      "skill": "skill-name",
      "path": "/absolute/path",
      "has_risk": true,
      "source_root": "/path/it/came/from",
      "flags": [
        {
          "dimension": "security|token_bloat|hidden_cost",
          "severity": "critical|high|medium|low",
          "rule": "rule-id",
          "detail": "说明",
          "file": "relative/file/path",
          "line": 42
        }
      ]
    }
  ],
  "clean": ["skill-a", "skill-b"]
}
```

### Step 3: Render the terminal report

Print in this order:

**1. Header**
```
OpenClaw Skill Auditor
扫描时间: 2026-03-16T12:00:00
扫描路径: ~/.openclaw/skills, ~/.agents/skills
共扫描 31 个 skill — 7 个有风险项，24 个正常
```

**2. 有风险的 skill 列表（仅列出有 flag 的）**

对每个有风险的 skill，按 dimension 分组输出所有 flag：

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1] baoyu-post-to-x
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔴 安全风险
    [CRITICAL] sec-exec — scripts/x-utils.ts:1
      调用 shell 执行（exec/subprocess/child_process），存在代码注入风险。
    [HIGH]     sec-cred — scripts/x-utils.ts:63
      读取凭证或密钥文件，请确认此操作是否必要且合法。

  🟡 Token 消耗
    [MEDIUM]   tok-duplicate-rules — SKILL.md
      SKILL.md 中有指令块重复出现 ≥3 次，存在冗余。

  🟠 隐性成本
    [CRITICAL] hid-cron-plant — scripts/x-utils.ts:179
      skill 植入了定时任务，会产生后台持续成本。
```

Severity 标签：`[CRITICAL]` `[HIGH]` `[MEDIUM]` `[LOW]`

Dimension 标题：
- `security`    → 🔴 安全风险
- `token_bloat` → 🟡 Token 消耗
- `hidden_cost` → 🟠 隐性成本

**3. 正常 skill**
```
✅ 以下 24 个 skill 未发现风险：
   agent-email-cli, exa-web-search-free, feishu-calendar ...
```

**4. 删除菜单**

```
以下 skill 存在风险项：
  [1] baoyu-post-to-x
  [2] ghost-scan-code

输入编号删除（如 1 3），或直接回车跳过：
```

等待用户回复后再操作。

### Step 4: 安全删除

对用户选中的每个 skill，根据其 `source_root` 确定实际路径，执行：

```bash
trash <skill-path>
```

若 `trash` 未安装，回退到：

```bash
mv <skill-path> ~/.Trash/
```

**绝对不用 `rm -rf`**。每删除一个都输出确认信息。删除后提示用户可重新扫描确认。

---

## 三个审计维度

### 安全（`sec-*`）

| 规则 | 检测内容 |
|------|---------|
| sec-eval | 脚本中的 `eval()` |
| sec-exec | `child_process` / `subprocess` / `os.system` 调用 shell |
| sec-exfil | 向外部主机发起网络请求（fetch/axios/curl/wget） |
| sec-cred | 读取 `.env`、`id_rsa`、API key、钱包文件等凭证 |
| sec-obfuscate | base64/十六进制链式解码（常见混淆手法） |
| sec-prompt-inject | SKILL.md 中的不可见字符、同形字、越狱指令 |
| sec-dynamic-import | 运行时路径的动态 import/require |

### Token 消耗（`tok-*`）

| 规则 | 检测内容 |
|------|---------|
| tok-skill-size | SKILL.md 超过 500 行 |
| tok-agents-embed | 引用或嵌入 AGENTS.md / CLAUDE.md / MEMORY.md |
| tok-duplicate-rules | 同一指令块在 SKILL.md 中重复 ≥3 次 |
| tok-ref-size | references/ 下单个文件超过 300 行 |
| tok-wide-trigger | 触发词过于宽泛（"any task"、"everything" 等） |

### 隐性成本（`hid-*`）

| 规则 | 检测内容 |
|------|---------|
| hid-heartbeat-abuse | skill 指示 agent 将自身加入 heartbeat 定时任务 |
| hid-cron-plant | 植入 cron / launchd / systemd 定时任务 |
| hid-self-reinstall | 通过 `npx skills add` 自我复制安装 |
| hid-always-load | 要求每次会话都预加载 |
| hid-tool-spam | 注册超过 10 个 MCP 工具 |

---

## 注意事项

- 扫描时自动跳过 `openclaw-skill-auditor` 本身。
- 若 `scan.py` 执行失败，直接报告错误原因和修复建议。
- 报告要直接，发现恶意模式就明确说是恶意，不要软化措辞。
- 删除菜单是可选的，绝不在用户确认前执行删除。
