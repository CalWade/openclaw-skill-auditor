---
name: openclaw-skill-auditor
description: Audit installed OpenClaw skills for security risks, token bloat, and hidden cost patterns. Use this skill whenever the user asks to scan, audit, check, or review their installed skills — including questions like "are my skills safe?", "which skills are wasting tokens?", "do I have any suspicious skills?", "clean up my skills", or "check my OpenClaw skills". Always invoke this skill for any skill health, quality, or cost investigation.
---

# OpenClaw Skill Auditor

扫描所有已安装的 OpenClaw skill，原样列出每一个命中项，由主人决定如何处理。

**核心原则：不做真实性判断。扫到什么就报什么，判断权在主人。**

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
共扫描 <skill_count> 个技能 — <flagged_count> 个有命中，<clean_count> 个正常
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

每个有命中的技能，按此格式输出。同一条规则在不同文件重复命中的，合并为一条、count 累加：

```
【N】<skill-name>

  🔴 安全问题
    · [严重] <detail>（共 <count> 处）
    · [高]   <detail>（共 <count> 处）

  🟡 Token 消耗
    · [中]   <detail>（共 <count> 处）

  🟠 隐性消耗
    · [高]   <detail>（共 <count> 处）
```

不输出文件名和行号。级别、说明、次数即可。

级别：`critical`→严重 / `high`→高 / `medium`→中 / `low`→低
维度：`security`→🔴 安全问题 / `token_bloat`→🟡 Token 消耗 / `hidden_cost`→🟠 隐性消耗

正常技能：

```
✅ 以下技能无命中（<clean_count> 个）：
   skill-a、skill-b ...
```

### Step 4: 优化建议（必须执行，不可跳过）

报告输出完毕后，**立即**根据 flags 生成建议。**禁止在此处加入任何判断或「简要说明」。**

遍历所有命中的技能，按以下映射生成建议条目，分配字母编号：

| flag 规则 | 建议文字 |
|-----------|---------|
| `tok-desc-length` | `<skill> 的 description 过长（N 字符），帮你精简到 150 字符以内？` |
| `tok-body-chars` | `<skill> 的 SKILL.md 正文约 N token，帮你把详细说明移到 references/？` |
| `tok-inline-code` / `tok-skill-size` / `tok-duplicate-rules` | `<skill> 的 SKILL.md 有冗余内容，帮你精简？` |
| `sec-eval` / `sec-exec` / `sec-exfil` / `sec-cred`（严重/高） | `<skill> 检测到高危代码模式，需要我打开文件逐行核查？` |
| `hid-cron-plant` / `hid-bg-process` / `hid-infinite-loop` | `<skill> 检测到后台持续运行模式，需要我查看代码确认是否必要？` |

合并：同一技能多条 tok-* 合并一条，多条安全/隐性问题合并一条。最多 8 条，severity 高的优先。

```
────────────────────────────────────────
可执行的优化建议
────────────────────────────────────────
  [A] feishu-permission-setup 检测到高危代码模式，需要我打开文件逐行核查？
  [B] skill-creator 的 SKILL.md 正文约 8000 token，帮你把详细说明移到 references/？
  [C] seo-content-writer 的 description 过长（876 字符），帮你精简到 150 字符以内？

输入字母执行（如：A C），或回车跳过：
```

### Step 5: 让主人决定删除

建议部分输出完、等待主人处理后，再输出：

```
────────────────────────────────────────
以上 <N> 个技能有命中项：
  【1】feishu-permission-setup
  【2】feishu-chat-reader
  ...

需要删除哪些？输入编号（如：1 3），或回车跳过：
```

**禁止在建议和删除之间插入任何判断、解释或「简要说明」。**

### Step 6: 安全删除

根据选中编号的 `source_root` + 技能名拼出完整路径，执行：

```bash
trash <skill-path>
```

若 `trash` 不可用：`mv <skill-path> ~/.Trash/`

**禁止 `rm -rf`。** 每删一个输出确认，删完后提示可重新扫描。

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
| tok-desc-length | description 超过 300 字符（每次都加载）|
| tok-body-chars | SKILL.md body 超过 8000 字符（约 2000 token）|
| tok-inline-code | SKILL.md 内嵌代码块超过 50 行 |
| tok-skill-size | SKILL.md 超过 500 行 |
| tok-agents-embed | 引用 AGENTS.md / CLAUDE.md / MEMORY.md |
| tok-duplicate-rules | 指令块重复 ≥3 次 |
| tok-ref-size | references/ 单文件超过 300 行 |
| tok-wide-trigger | 触发词过于宽泛 |

### 隐性消耗（`hid-*`）

| 规则 | 检测内容 |
|------|---------|
| hid-heartbeat-abuse | 指示加入 heartbeat 定时任务 |
| hid-cron-plant | 植入 cron/launchd/systemd 定时任务 |
| hid-self-reinstall | `npx skills add` 自我复制 |
| hid-always-load | 要求每次会话预加载 |
| hid-tool-spam | 注册超过 10 个 MCP 工具 |
| hid-bg-process | nohup/pm2/forever/daemon 后台持久进程 |
| hid-infinite-loop | `while True` / `while(true)` 无限循环 |
| hid-set-interval | `setInterval` 或递归 `setTimeout` |
| hid-websocket | WebSocket 长连接 |
| hid-sleep-loop | sleep 调用（常与循环结合实现轮询）|

---

## 注意事项

- 扫描时自动跳过 `openclaw-skill-auditor` 本身。
- scan.py 会跳过 markdown 文件中的代码块内容，以减少文档示例触发的误报。
- 若 `scan.py` 执行失败，直接报告错误命令和原因。
- **禁止在报告中加入"判断"、"这属于正常行为"、"可以忽略"、"简要说明"之类的文字。扫到什么列什么，判断权在主人。**
