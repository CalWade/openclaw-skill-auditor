---
name: openclaw-skill-auditor
description: 扫描并审计所有已安装的 OpenClaw 技能，检测安全风险、token 消耗和隐性成本。当用户说以下任意内容时触发：扫描技能、审计技能、检查技能、技能安全、技能有没有问题、技能质量、技能清理、哪些技能有风险、技能消耗太多token、技能有恶意代码、有没有危险的技能、技能后台任务、技能定时任务、检查我的skill、扫描我的skill、skill安全、skill审计、skill有问题、清理skill、skill质量检测、skill太占token、有没有可疑的skill。Always invoke this skill for any skill health, security, quality, token cost, or background task investigation.
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
  --out ./oca_audit.json
```

Additional path: append `--extra-root /path/to/skills`.

### Step 2: Read and render

Read `./oca_audit.json` and print the report exactly as specified below. Do not add commentary, do not filter flags, do not explain away findings.

### Step 3: Terminal report format

Header:

```
════════════════════════════════════════
技能安全审计报告
扫描时间：<scanned_at>
共扫描 <skill_count> 个技能 — <flagged_count> 个有命中，<clean_count> 个正常
════════════════════════════════════════
```

每个有命中的技能，按此格式输出。同一条规则在不同文件重复命中的，合并为一条、count 累加。不输出文件名和行号。序号用 emoji 数字（1️⃣2️⃣3️⃣...），维度标题前缀 `--`，条目前缀 `----`，无空格缩进：

```
1️⃣<skill-name>
--🔴 安全问题
----[严重] <detail>（共 <count> 处）
----[高] <detail>（共 <count> 处）
--🟡 Token 消耗
----[中] <detail>（共 <count> 处）
--🟠 隐性消耗
----[高] <detail>（共 <count> 处）

2️⃣<skill-name>
--🔴 安全问题
----[高] <detail>（共 <count> 处）
```

级别：`critical`→严重 / `high`→高 / `medium`→中 / `low`→低
维度：`security`→🔴 安全问题 / `token_bloat`→🟡 Token 消耗 / `hidden_cost`→🟠 隐性消耗

正常技能：

```
✅ 以下技能无命中（<clean_count> 个）：
skill-a、skill-b、skill-c ...
```

### Step 4: 处置建议（必须执行，不可跳过）

报告输出完毕后，**立即**逐技能输出处置建议。**每个有命中的技能都必须给出建议，覆盖所有命中的维度。** 禁止加入任何主观判断。

每个技能最多三条建议（安全 / Token消耗 / 隐性消耗各一条），按以下模板映射，分配字母编号：

**安全问题（有任意 sec-* 命中时生成）：**

| 命中情况 | 建议文字 |
|---------|---------|
| 仅 `sec-exfil` | `帮你检查 <skill> 的网络请求目标地址，确认是否只访问合法域名？` |
| 仅 `sec-cred` | `帮你核查 <skill> 读取的凭证文件路径，确认权限范围是否合理？` |
| 仅 `sec-eval` / `sec-exec` | `帮你逐行核查 <skill> 的可执行代码，确认是否存在注入风险？` |
| 多条 sec-* 同时命中 | `帮你逐行核查 <skill> 的安全问题（列出类型：执行/网络/凭证），确认风险范围？` |

**Token 消耗（有任意 tok-* 命中时生成）：**

| 命中情况 | 建议文字 |
|---------|---------|
| `tok-desc-length` | `帮你把 <skill> 的 description 精简到 150 字符以内？` |
| `tok-body-chars` / `tok-skill-size` | `帮你把 <skill> 的 SKILL.md 详细内容移到 references/ 按需加载？` |
| `tok-duplicate-rules` | `帮你删除 <skill> 的 SKILL.md 中重复的指令块？` |
| 多条 tok-* 同时命中 | `帮你精简 <skill> 的 SKILL.md，减少每次加载的 token 消耗？` |

**隐性消耗（有任意 hid-* 命中时生成）：**

| 命中情况 | 建议文字 |
|---------|---------|
| `hid-cron-plant` / `hid-bg-process` | `帮你核查 <skill> 的后台进程启动逻辑，确认是否必要且受控？` |
| `hid-infinite-loop` / `hid-sleep-loop` | `帮你核查 <skill> 的循环逻辑，确认是否会持续占用资源？` |
| `hid-websocket` / `hid-set-interval` | `帮你核查 <skill> 的长连接/定时逻辑，确认生命周期是否可控？` |
| `hid-self-reinstall` / `hid-heartbeat-abuse` | `帮你核查 <skill> 是否会自动触发重复执行？` |
| 多条 hid-* 同时命中 | `帮你核查 <skill> 的后台持续行为（列出类型），确认是否受控？` |

输出格式，按技能分组，条目前缀 `--`，无空格缩进：

```
────────────────────────────────────────
处置建议
────────────────────────────────────────
1️⃣feishu-chat-reader
--[A] 帮你逐行核查 feishu-chat-reader 的安全问题（网络请求/凭证读取），确认风险范围？
--[B] 帮你核查 feishu-chat-reader 的循环逻辑，确认是否会持续占用资源？
2️⃣feishu-permission-setup
--[C] 帮你逐行核查 feishu-permission-setup 的安全问题（代码执行/凭证读取），确认风险范围？
3️⃣us-stock-analysis
--[D] 帮你检查 us-stock-analysis 的网络请求目标地址，确认是否只访问合法域名？
4️⃣weather
--[E] 帮你检查 weather 的网络请求目标地址，确认是否只访问合法域名？

输入字母执行（如：A C），或回车跳过：
```

### Step 5: 让主人决定删除

建议部分输出完、等待主人处理完之后，再输出：

```
────────────────────────────────────────
以上 <N> 个技能有命中项：
--1️⃣feishu-permission-setup
--2️⃣feishu-chat-reader
--...
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
