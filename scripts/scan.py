#!/usr/bin/env python3
"""
OpenClaw Skill Auditor - Static scanner
Scans installed OpenClaw skills for security, token bloat, and hidden cost risks.

Usage:
    python3 scan.py [--out /tmp/openclaw-audit.json] [--extra-root /path/to/skills]
"""

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path


@dataclass
class Flag:
    dimension: str   # security | token_bloat | hidden_cost
    severity: str    # critical | high | medium | low
    rule: str        # rule-id
    detail: str      # human-readable warning
    file: str        # relative path within skill dir
    line: int = 0    # 0 = file-level


CONTENT_RULES = [
    # Security
    (
        "sec-eval", "security", "critical",
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        "eval() 可在运行时执行任意注入代码。",
    ),
    (
        "sec-exec", "security", "critical",
        re.compile(
            r"exec\s*\(|child_process|subprocess\.(run|call|Popen|check_output)|os\.system\s*\(",
            re.IGNORECASE,
        ),
        "调用 shell 执行（exec/subprocess/child_process），存在代码注入风险。",
    ),
    (
        "sec-exfil", "security", "high",
        re.compile(
            r"\b(fetch|axios|requests\.(get|post|put|delete|patch)|curl|wget)\b.*https?://(?!localhost|127\.0\.0\.1)",
            re.IGNORECASE,
        ),
        "向外部主机发起网络请求，可能存在数据外泄。",
    ),
    (
        "sec-cred", "security", "high",
        re.compile(
            r"(\.env|id_rsa|id_ed25519|\.pem|api[_-]?key|secret[_-]?key|wallet\.json|keystore)",
            re.IGNORECASE,
        ),
        "读取凭证或密钥文件，请确认此操作是否必要且合法。",
    ),
    (
        "sec-obfuscate", "security", "high",
        re.compile(
            r"(base64\.b64decode|Buffer\.from\([^,]+,\s*['\"]base64['\"]|\\x[0-9a-f]{2}){3,}",
            re.IGNORECASE,
        ),
        "存在 base64/十六进制链式解码，是常见的代码混淆手法。",
    ),
    (
        "sec-dynamic-import", "security", "medium",
        re.compile(r"(await\s+import\s*\(\s*[^'\"(]|require\s*\(\s*[^'\"(])", re.IGNORECASE),
        "动态 import 路径由运行时计算，可能加载任意模块。",
    ),
    (
        "sec-prompt-inject", "security", "critical",
        re.compile(
            r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]"
            r"|[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]"
            r"|(ignore (all |previous )?(instructions?|rules?|guidelines?))",
            re.IGNORECASE,
        ),
        "SKILL.md 中检测到不可见字符、同形字或越狱指令，疑似 Prompt 注入攻击。",
    ),
    # Token Bloat
    (
        "tok-agents-embed", "token_bloat", "medium",
        re.compile(r"(AGENTS\.md|CLAUDE\.md|MEMORY\.md)", re.IGNORECASE),
        "引用或嵌入了工作区配置文件，每次调用都会将其拉入上下文消耗 token。",
    ),
    (
        "tok-wide-trigger", "token_bloat", "low",
        re.compile(
            r"\b(any task|everything|all tasks|always use this skill|use for all|use this for everything)\b",
            re.IGNORECASE,
        ),
        "触发词过于宽泛，可能导致 skill 被不必要地频繁激活。",
    ),
    # Hidden Cost
    (
        "hid-heartbeat-abuse", "hidden_cost", "high",
        re.compile(
            r"(HEARTBEAT\.md|add.*to.*heartbeat|run.*periodically|schedule.*this skill)",
            re.IGNORECASE,
        ),
        "skill 指示 agent 将自身加入 heartbeat 定时任务，导致持续 token 消耗。",
    ),
    (
        "hid-cron-plant", "hidden_cost", "critical",
        re.compile(
            r"(crontab|launchd|\.plist|systemd|\.timer|schedule\.every)",
            re.IGNORECASE,
        ),
        "skill 植入了 cron/launchd/systemd 定时任务，会产生后台持续成本。",
    ),
    (
        "hid-self-reinstall", "hidden_cost", "high",
        re.compile(r"npx skills add", re.IGNORECASE),
        "skill 尝试安装或重新安装自身/其他 skill，存在自我复制行为。",
    ),
    (
        "hid-always-load", "hidden_cost", "medium",
        re.compile(
            r"\b(always load|load on every session|load at startup|preload this skill)\b",
            re.IGNORECASE,
        ),
        "skill 要求每次会话都预加载，会增加每轮对话的固定 token 开销。",
    ),
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".tar", ".bin", ".pyc",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".bash", ".zsh",
    ".json", ".md", ".txt", ".yaml", ".yml", ".toml", ".html", ".css",
}

DUPLICATE_WINDOW = 5
DUPLICATE_THRESHOLD = 3


def scan_content(skill_path: Path) -> list:
    flags = []
    seen = set()
    for fpath in skill_path.rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() in SKIP_EXTENSIONS:
            continue
        if fpath.suffix.lower() not in TEXT_EXTENSIONS and fpath.suffix != "":
            continue
        if "openclaw-skill-auditor" in str(fpath):
            continue
        rel = str(fpath.relative_to(skill_path))
        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for rule_id, dimension, severity, pattern, detail in CONTENT_RULES:
                key = f"{rule_id}:{rel}"
                if key in seen:
                    continue
                if pattern.search(line):
                    flags.append(Flag(dimension, severity, rule_id, detail, rel, line=lineno))
                    seen.add(key)
    return flags


def check_skill_size(skill_path: Path):
    md = skill_path / "SKILL.md"
    if not md.exists():
        return None
    n = len(md.read_text(errors="replace").splitlines())
    if n > 500:
        return Flag(
            "token_bloat", "medium", "tok-skill-size",
            f"SKILL.md 共 {n} 行（超过 500 行），建议将内容移至 references/ 目录。",
            "SKILL.md",
        )
    return None


def check_ref_size(skill_path: Path) -> list:
    flags = []
    refs = skill_path / "references"
    if not refs.exists():
        return flags
    for f in refs.rglob("*"):
        if f.is_file() and f.suffix in (".md", ".txt", ".rst"):
            n = len(f.read_text(errors="replace").splitlines())
            if n > 300:
                flags.append(Flag(
                    "token_bloat", "low", "tok-ref-size",
                    f"references 文件共 {n} 行（超过 300 行），建议拆分或精简。",
                    str(f.relative_to(skill_path)),
                ))
    return flags


def check_duplicate_blocks(skill_path: Path):
    md = skill_path / "SKILL.md"
    if not md.exists():
        return None
    lines = md.read_text(errors="replace").splitlines()
    counts = Counter()
    for i in range(len(lines) - DUPLICATE_WINDOW + 1):
        block = "\n".join(lines[i:i + DUPLICATE_WINDOW]).strip()
        if block:
            counts[block] += 1
    repeated = [b for b, c in counts.items() if c >= DUPLICATE_THRESHOLD]
    if repeated:
        return Flag(
            "token_bloat", "medium", "tok-duplicate-rules",
            f"SKILL.md 中有 {len(repeated)} 个指令块重复出现 ≥{DUPLICATE_THRESHOLD} 次，存在冗余。",
            "SKILL.md",
        )
    return None


def check_mcp_tools(skill_path: Path):
    for fname in ("mcp.json", "tools.json", "mcp_tools.json"):
        fpath = skill_path / fname
        if fpath.exists():
            try:
                data = json.loads(fpath.read_text())
                tools = data.get("tools", [])
                if len(tools) > 10:
                    return Flag(
                        "hidden_cost", "medium", "hid-tool-spam",
                        f"{fname} 注册了 {len(tools)} 个工具（超过 10 个），会使每次 tool-call 的上下文膨胀。",
                        fname,
                    )
            except (json.JSONDecodeError, KeyError):
                pass
    return None


def audit_skill(skill_path: Path) -> dict:
    flags = []
    flags.extend(scan_content(skill_path))
    f = check_skill_size(skill_path)
    if f:
        flags.append(f)
    flags.extend(check_ref_size(skill_path))
    f = check_duplicate_blocks(skill_path)
    if f:
        flags.append(f)
    f = check_mcp_tools(skill_path)
    if f:
        flags.append(f)
    return {
        "skill": skill_path.name,
        "path": str(skill_path),
        "has_risk": len(flags) > 0,
        "flags": [asdict(f) for f in flags],
    }


def resolve_skill_roots(extra=None) -> list:
    home = Path.home()
    candidates = []
    workspace = home / ".openclaw" / "workspace"
    config_file = home / ".openclaw" / "openclaw.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            ws = cfg.get("agents", {}).get("defaults", {}).get("workspace")
            if ws:
                workspace = Path(ws).expanduser()
        except (json.JSONDecodeError, KeyError):
            pass
    candidates.append(workspace / "skills")
    candidates.append(home / ".openclaw" / "skills")
    candidates.append(home / ".agents" / "skills")
    if extra:
        for p in extra:
            candidates.append(Path(p).expanduser())
    seen = set()
    roots = []
    for p in candidates:
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        if resolved not in seen and p.exists():
            seen.add(resolved)
            roots.append(p)
    return roots


def run(roots, out: Path) -> int:
    if not roots:
        print("ERROR: 未找到任何 skill 目录。", file=sys.stderr)
        print("已查找: ~/.openclaw/workspace/skills, ~/.openclaw/skills, ~/.agents/skills", file=sys.stderr)
        return 1
    seen_names = set()
    skill_dirs = []
    for root in roots:
        for d in sorted(root.iterdir(), key=lambda x: x.name):
            if not d.is_dir() or d.name.startswith("."):
                continue
            if d.name == "openclaw-skill-auditor":
                continue
            if d.name not in seen_names:
                seen_names.add(d.name)
                skill_dirs.append((d, str(root)))
    print(f"扫描 {len(skill_dirs)} 个 skill，覆盖 {len(roots)} 个路径：")
    for root in roots:
        print(f"  {root}")
    results = []
    for skill_dir, source in skill_dirs:
        result = audit_skill(skill_dir)
        result["source_root"] = source
        results.append(result)
    flagged = [r for r in results if r["has_risk"]]
    clean = [r for r in results if not r["has_risk"]]
    report = {
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "roots": [str(r) for r in roots],
        "skill_count": len(results),
        "flagged_count": len(flagged),
        "clean_count": len(clean),
        "flagged": flagged,
        "clean": [r["skill"] for r in clean],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"完成。{len(flagged)} 个 skill 有风险项，{len(clean)} 个无风险。报告: {out}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="OpenClaw Skill Auditor")
    parser.add_argument(
        "--extra-root",
        action="append",
        metavar="DIR",
        help="额外扫描路径（可重复使用）。标准路径始终自动扫描。",
    )
    parser.add_argument(
        "--out",
        default="/tmp/openclaw-audit.json",
        help="JSON 报告输出路径（默认: /tmp/openclaw-audit.json）",
    )
    args = parser.parse_args()
    roots = resolve_skill_roots(args.extra_root)
    sys.exit(run(roots, Path(args.out).expanduser()))


if __name__ == "__main__":
    main()
