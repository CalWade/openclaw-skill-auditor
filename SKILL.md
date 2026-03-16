---
name: openclaw-skill-auditor
description: Audit installed OpenClaw skills for security risks, token bloat, and hidden cost patterns. Use this skill whenever the user asks to scan, audit, check, or review their installed skills — including questions like "are my skills safe?", "which skills are wasting tokens?", "do I have any suspicious skills?", "clean up my skills", or "check my OpenClaw skills". Always invoke this skill for any skill health, quality, or cost investigation.
---

# OpenClaw Skill Auditor

扫描所有已安装的 OpenClaw skill，原样列出每一个命中项，由主人决定如何处理。

**核心原则：你不做真实性判断。扫到什么就报什么，判断权在主人。**

## Overview

The auditor runs `scripts/scan.py`, which automatically discovers and scans **all** OpenClaw skill directories:

1. `<workspace>/skills` — workspace-level (reads from `~/.openclaw/openclaw.json`)
2. `~/.openclaw/skills` — user-managed skills
3. `~/.agents/skills` — legacy path used by the `npx skills` CLI

Skills with the same name across paths are deduplicated (first occurrence wins). The script skips content inside markdown code fences to reduce documentation false positives.

## Workflow

### Step 1: Run the scanner

```bash
python3 ~/.openclaw/skills/openclaw-skill-auditor/scripts/scan.py \
  --out /tmp/openclaw-audit.json
```

Additional path: append `--extra-root /path/to/skills`.

### Step 2: Read and render

Read `/tmp/openclaw-audit.json` and print the report exactly as specified below. Do not add commentary, do not filter flags, do not explain away findings.

### Step 3: Terminal report format

Header:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Skill Auditor 扫描报告
扫描时间：<scanned_at>
共扫描 <skill_count> 个 skill — <flagged_count> 个有命中项，<clean_count> 个无命中
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

每个有命中的 skill，按此格式输出：

```
[N] <skill-name>  (<source_root>)

  🔴 安全风险        ← 仅当有 security flags 时显示
    [SEVERITY] <rule> — <file>:<line> — <detail>（<count>处）

  🟡 Token 消耗      ← 仅当有 token_bloat flags 时显示
    [SEVERITY] <rule> — <file>:<line> — <detail>（<count>处）

  🟠 隐性成本        ← 仅当有 hidden_cost flags 时显示
    [SEVERITY] <rule> — <file>:<line> — <detail>（<count>处）
```

Severity 标签：`[CRITICAL]` `[HIGH]` `[MEDIUM]` `[LOW]`

正常 skill：

```
✅ 无命中（<clean_count> 个）：<skill1>, <skill2>, ...
```

### Step 4: 让主人决定

列出所有有命中项的 skill 编号，直接问主人：

```
以上 <N> 个 skill 有命中项。

请问需要删除哪些？输入编号（如 1 3），或回车跳过：
```

**不要在问题前加任何分析、建议或判断。** 直接列编号，直接问。

### Step 5: 安全删除

对主人选中的每个 skill，根据 `source_root` 确定路径，执行：

```bash
trash <skill-path>
```

若 `trash` 不可用：

```bash
mv <skill-path> ~/.Trash/
```

**禁止使用 `rm -rf`。** 每删一个输出确认，删完后提示可重新扫描。

---

## 三个检测维度

### 安全（`sec-*`）

| 规则 | 检测内容 |
|------|---------|
| sec-eval | `eval()` |
| sec-exec | `child_process` / `subprocess` / `os.system` |
| sec-exfil | 网络请求（fetch/axios/curl/wget） |
| sec-cred | `.env`、`id_rsa`、API key、钱包文件等 |
| sec-obfuscate | base64/十六进制链式解码 |
| sec-prompt-inject | 不可见字符、同形字、越狱指令 |
| sec-dynamic-import | 运行时路径动态 import/require |

### Token 消耗（`tok-*`）

| 规则 | 检测内容 |
|------|---------|
| tok-skill-size | SKILL.md 超过 500 行 |
| tok-agents-embed | 引用 AGENTS.md / CLAUDE.md / MEMORY.md |
| tok-duplicate-rules | 指令块重复 ≥3 次 |
| tok-ref-size | references/ 单文件超过 300 行 |
| tok-wide-trigger | 触发词过于宽泛 |

### 隐性成本（`hid-*`）

| 规则 | 检测内容 |
|------|---------|
| hid-heartbeat-abuse | 指示加入 heartbeat 定时任务 |
| hid-cron-plant | 植入 cron/launchd/systemd 定时任务 |
| hid-self-reinstall | `npx skills add` 自我复制 |
| hid-always-load | 要求每次会话预加载 |
| hid-tool-spam | 注册超过 10 个 MCP 工具 |

---

## 注意事项

- 扫描时自动跳过 `openclaw-skill-auditor` 本身。
- scan.py 会跳过 markdown 文件中的代码块内容，以减少文档示例触发的误报。
- 若 `scan.py` 执行失败，直接报告错误命令和原因。
- **禁止在报告中加入"判断"、"这属于正常行为"、"可以忽略"之类的文字。扫到什么列什么，主人决定要不要删。**
