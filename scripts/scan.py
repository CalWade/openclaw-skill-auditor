#!/usr/bin/env python3
"""
OpenClaw Skill Auditor - Static scanner
Scans installed OpenClaw skills for security, token bloat, and hidden cost risks.

Priority-based scanning:
  Tier 1 — always fully scanned: SKILL.md, scripts/, root-level files <= 64 KB
  Tier 2 — scanned until budget: remaining subdirs, depth <= 6, files <= 256 KB
  Markdown code fences stripped before scanning to suppress doc false positives.

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

TIER1_MAX_BYTES   = 64  * 1024
TIER2_MAX_BYTES   = 256 * 1024
TIER2_FILE_BUDGET = 120
MAX_LINES_READ    = 5000
MAX_SCAN_DEPTH    = 6

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", "coverage", ".cache", "eval-viewer",
    ".next", ".nuxt", "vendor", ".yarn",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".tar", ".bin", ".pyc", ".map",
    ".lock", ".exe", ".dll", ".so", ".dylib",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".bash", ".zsh",
    ".json", ".md", ".txt", ".yaml", ".yml", ".toml", ".html", ".css",
    ".mjs", ".cjs", ".jsx", ".tsx",
}


@dataclass
class Flag:
    dimension: str
    severity: str
    rule: str
    detail: str
    file: str
    line: int = 0
    count: int = 1


CONTENT_RULES = [
    (
        "sec-eval", "security", "critical",
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        "eval() 可在运行时执行任意注入代码。",
    ),
    (
        "sec-exec", "security", "critical",
        re.compile(
            r"child_process|subprocess\s*\.\s*(run|call|Popen|check_output)"
            r"|os\s*\.\s*system\s*\("
            r"|\bexec\s*\(\s*['\"`]",
            re.IGNORECASE,
        ),
        "调用 shell 执行（exec/subprocess/child_process），存在代码注入风险。",
    ),
    (
        "sec-exfil", "security", "high",
        re.compile(
            r"\b(fetch|axios|requests\s*\.\s*(get|post|put|delete|patch)|curl|wget)\b",
            re.IGNORECASE,
        ),
        "发起网络请求，请确认目标地址是否合法（非本地）。",
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
            r"base64\.b64decode"
            r"|Buffer\.from\s*\([^,\n]{0,80},\s*['\"]base64['\"]"
            r"|(\\x[0-9a-fA-F]{2}){4,}",
        ),
        "存在 base64/十六进制解码，是常见的代码混淆手法。",
    ),
    (
        "sec-dynamic-import", "security", "medium",
        re.compile(
            r"await\s+import\s*\(\s*(?!['\"`])"
            r"|require\s*\(\s*(?!['\"`])",
            re.IGNORECASE,
        ),
        "动态 import 路径由运行时变量决定，可能加载任意模块。",
    ),
    (
        "sec-prompt-inject", "security", "critical",
        re.compile(
            r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]"
            r"|[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]"
            r"|\bignore\s+(all\s+|previous\s+)?(instructions?|rules?|guidelines?)\b",
            re.IGNORECASE,
        ),
        "SKILL.md 中检测到不可见字符、同形字或越狱指令，疑似 Prompt 注入攻击。",
    ),
    (
        "tok-agents-embed", "token_bloat", "medium",
        re.compile(r"\b(AGENTS\.md|CLAUDE\.md|MEMORY\.md)\b", re.IGNORECASE),
        "引用或嵌入工作区配置文件，每次调用都会将其拉入上下文消耗 token。",
    ),
    (
        "tok-wide-trigger", "token_bloat", "low",
        re.compile(
            r"\b(any task|everything|all tasks|always use this skill|use for all|use this for everything)\b",
            re.IGNORECASE,
        ),
        "触发词过于宽泛，可能导致 skill 被不必要地频繁激活。",
    ),
    (
        "hid-heartbeat-abuse", "hidden_cost", "high",
        re.compile(
            r"HEARTBEAT\.md"
            r"|add\s+.{0,30}\s+to\s+.{0,30}\s+heartbeat"
            r"|run\s+periodically"
            r"|schedule\s+this\s+skill",
            re.IGNORECASE,
        ),
        "skill 指示 agent 将自身加入 heartbeat 定时任务，导致持续 token 消耗。",
    ),
    (
        "hid-cron-plant", "hidden_cost", "critical",
        re.compile(
            r"\bcrontab\b|launchd|\bsystemd\b|\.timer\b|schedule\.every",
            re.IGNORECASE,
        ),
        "skill 植入了 cron/launchd/systemd 定时任务，会产生后台持续成本。",
    ),
    (
        "hid-self-reinstall", "hidden_cost", "high",
        re.compile(r"npx\s+skills\s+add", re.IGNORECASE),
        "skill 尝试安装或重新安装自身/其他 skill，存在自我复制行为。",
    ),
    (
        "hid-always-load", "hidden_cost", "medium",
        re.compile(
            r"\b(always\s+load|load\s+on\s+every\s+session|load\s+at\s+startup|preload\s+this\s+skill)\b",
            re.IGNORECASE,
        ),
        "skill 要求每次会话都预加载，会增加每轮对话的固定 token 开销。",
    ),
]

DUPLICATE_WINDOW    = 5
DUPLICATE_THRESHOLD = 3


def _is_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.suffix == ""


def _skip(path: Path) -> bool:
    return path.suffix.lower() in SKIP_EXTENSIONS


def collect_tier1(skill_path: Path) -> list:
    files = []
    skill_md = skill_path / "SKILL.md"
    if skill_md.exists() and skill_md.is_file():
        files.append(skill_md)
    scripts_dir = skill_path / "scripts"
    if scripts_dir.exists():
        for f in sorted(scripts_dir.rglob("*")):
            if f.is_file() and _is_text(f) and not _skip(f):
                try:
                    if f.stat().st_size <= TIER1_MAX_BYTES:
                        files.append(f)
                except OSError:
                    pass
    for f in sorted(skill_path.iterdir()):
        if f.is_file() and _is_text(f) and not _skip(f) and f != skill_md:
            try:
                if f.stat().st_size <= TIER1_MAX_BYTES:
                    files.append(f)
            except OSError:
                pass
    seen = set()
    result = []
    for f in files:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


def collect_tier2(skill_path: Path, already_scanned: set) -> list:
    candidates = []

    def _walk(directory: Path, depth: int):
        if depth > MAX_SCAN_DEPTH:
            return
        try:
            entries = sorted(directory.iterdir())
        except PermissionError:
            return
        for entry in entries:
            if entry.is_dir():
                if entry.name in SKIP_DIRS or entry.name.startswith("."):
                    continue
                if entry == skill_path / "scripts":
                    continue
                _walk(entry, depth + 1)
            elif entry.is_file():
                if entry in already_scanned or _skip(entry) or not _is_text(entry):
                    continue
                try:
                    size = entry.stat().st_size
                except OSError:
                    continue
                if size > TIER2_MAX_BYTES:
                    continue
                candidates.append((depth, size, entry))

    _walk(skill_path, 1)
    candidates.sort(key=lambda x: (x[0], x[1]))
    return [f for _, _, f in candidates[:TIER2_FILE_BUDGET]]


def strip_markdown_fences(lines: list) -> list:
    """
    Replace lines inside ``` fences with empty strings.
    Prevents doc examples from triggering rules.
    Line numbers are preserved so positions remain accurate.
    """
    result = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            result.append("")
        elif in_fence:
            result.append("")
        else:
            result.append(line)
    return result


def scan_file(fpath: Path, skill_path: Path) -> list:
    try:
        text = fpath.read_text(errors="replace")
    except OSError:
        return []
    lines = text.splitlines()[:MAX_LINES_READ]
    if fpath.suffix.lower() == ".md":
        lines = strip_markdown_fences(lines)
    rel = str(fpath.relative_to(skill_path))
    hits = {}
    for lineno, line in enumerate(lines, 1):
        for rule_id, dimension, severity, pattern, detail in CONTENT_RULES:
            if pattern.search(line):
                if rule_id not in hits:
                    hits[rule_id] = [lineno, 0, dimension, severity, detail]
                hits[rule_id][1] += 1
    return [
        Flag(dimension, severity, rule_id, detail, rel, line=first_line, count=count)
        for rule_id, (first_line, count, dimension, severity, detail) in hits.items()
    ]


def check_skill_size(skill_path: Path):
    md = skill_path / "SKILL.md"
    if not md.exists():
        return None
    try:
        n = len(md.read_text(errors="replace").splitlines())
    except OSError:
        return None
    if n > 500:
        return Flag("token_bloat", "medium", "tok-skill-size",
            f"SKILL.md 共 {n} 行（超过 500 行），建议将内容移至 references/ 目录。", "SKILL.md")
    return None


def check_ref_size(skill_path: Path) -> list:
    flags = []
    refs = skill_path / "references"
    if not refs.exists():
        return flags
    try:
        entries = list(refs.rglob("*"))
    except PermissionError:
        return flags
    for f in entries:
        if not f.is_file() or f.suffix not in (".md", ".txt", ".rst"):
            continue
        try:
            if f.stat().st_size > TIER2_MAX_BYTES:
                continue
            n = len(f.read_text(errors="replace").splitlines())
        except OSError:
            continue
        if n > 300:
            flags.append(Flag("token_bloat", "low", "tok-ref-size",
                f"references 文件共 {n} 行（超过 300 行），建议拆分或精简。",
                str(f.relative_to(skill_path))))
    return flags


def check_duplicate_blocks(skill_path: Path):
    md = skill_path / "SKILL.md"
    if not md.exists():
        return None
    try:
        lines = md.read_text(errors="replace").splitlines()[:MAX_LINES_READ]
    except OSError:
        return None
    counts = Counter()
    for i in range(len(lines) - DUPLICATE_WINDOW + 1):
        block = "\n".join(lines[i:i + DUPLICATE_WINDOW]).strip()
        if block:
            counts[block] += 1
    repeated = [b for b, c in counts.items() if c >= DUPLICATE_THRESHOLD]
    if repeated:
        return Flag("token_bloat", "medium", "tok-duplicate-rules",
            f"SKILL.md 中有 {len(repeated)} 个指令块重复出现 ≥{DUPLICATE_THRESHOLD} 次，存在冗余。",
            "SKILL.md")
    return None


def check_mcp_tools(skill_path: Path):
    for fname in ("mcp.json", "tools.json", "mcp_tools.json"):
        fpath = skill_path / fname
        if not fpath.exists():
            continue
        try:
            if fpath.stat().st_size > TIER2_MAX_BYTES:
                continue
            data = json.loads(fpath.read_text())
            tools = data.get("tools", [])
            if len(tools) > 10:
                return Flag("hidden_cost", "medium", "hid-tool-spam",
                    f"{fname} 注册了 {len(tools)} 个工具（超过 10 个），会使每次 tool-call 的上下文膨胀。",
                    fname)
        except (OSError, json.JSONDecodeError, KeyError):
            pass
    return None


def audit_skill(skill_path: Path) -> dict:
    flags = []
    tier1_files = collect_tier1(skill_path)
    tier1_set = set(tier1_files)
    for fpath in tier1_files:
        flags.extend(scan_file(fpath, skill_path))
    tier2_files = collect_tier2(skill_path, tier1_set)
    for fpath in tier2_files:
        flags.extend(scan_file(fpath, skill_path))
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
        "scanned_files": len(tier1_files) + len(tier2_files),
        "tier1_files": len(tier1_files),
        "tier2_files": len(tier2_files),
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
        print("已查找: ~/.openclaw/workspace/skills, ~/.openclaw/skills, ~/.agents/skills",
              file=sys.stderr)
        return 1
    seen_names: set = set()
    skill_dirs = []
    for root in roots:
        try:
            entries = sorted(root.iterdir(), key=lambda x: x.name)
        except PermissionError:
            continue
        for d in entries:
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
    clean   = [r for r in results if not r["has_risk"]]
    report = {
        "scanned_at":    datetime.now().isoformat(timespec="seconds"),
        "roots":         [str(r) for r in roots],
        "skill_count":   len(results),
        "flagged_count": len(flagged),
        "clean_count":   len(clean),
        "flagged":       flagged,
        "clean":         [r["skill"] for r in clean],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"完成。{len(flagged)} 个 skill 有命中项，{len(clean)} 个无命中。报告: {out}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="OpenClaw Skill Auditor")
    parser.add_argument("--extra-root", action="append", metavar="DIR",
        help="额外扫描路径（可重复使用）。标准路径始终自动扫描。")
    parser.add_argument("--out", default="/tmp/openclaw-audit.json",
        help="JSON 报告输出路径（默认: /tmp/openclaw-audit.json）")
    args = parser.parse_args()
    roots = resolve_skill_roots(args.extra_root)
    sys.exit(run(roots, Path(args.out).expanduser()))


if __name__ == "__main__":
    main()
