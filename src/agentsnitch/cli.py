"""agentsnitch: what did your AI coding agents actually do on your machine?"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, agentlogs
from .audit import Audit, run
from .rules import HIGH, LOW, MEDIUM

SEV_STYLE = {HIGH: "bold red", MEDIUM: "yellow", LOW: "dim"}
SEV_LABEL = {HIGH: "high", MEDIUM: "medium", LOW: "low"}
AGENT_NAME = {"claude": "Claude Code", "codex": "Codex", "gemini": "Gemini CLI"}


def short_path(p: str) -> str:
    home = str(Path.home())
    return "~" + p[len(home):] if p.startswith(home) else p


def when(ts: float | None) -> str:
    if not ts:
        return ""
    d = time.time() - ts
    if d < 3600:
        return f"{max(1, int(d // 60))}m ago"
    if d < 86400:
        return f"{int(d // 3600)}h ago"
    return time.strftime("%b %d", time.localtime(ts))


def one_line(s: str, n: int = 70) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def render(a: Audit, console: Console, show: int = 6, include_low: bool = False) -> None:
    if not a.actions:
        console.print(Text("No agent activity found. agentsnitch reads Claude Code, Codex and Gemini CLI logs from "
                           "your home folder; if you use them, try --since all.", "yellow"))
        return
    head = Text.assemble("Your coding agents ran ", (f"{a.commands:,} commands", "bold"), f" {a.period()}",
                         f", read {a.reads:,} files and wrote {a.writes:,}.")
    n_s, n_p = len(a.sessions), len(a.projects)
    sub = Text(f"{n_s} session{'s' * (n_s != 1)} · {n_p} project{'s' * (n_p != 1)} · " +
               " · ".join(f"{AGENT_NAME.get(k, k)} {v:,}" for k, v in a.agents.most_common() if v), "dim")
    parts: list = [head, sub, Text("")]
    hl = a.highlights()
    if hl:
        parts += [Text("  ·  ".join(hl), "bold red"), Text("")]

    rows = [r for r in a.by_rule() if include_low or r[1] != LOW]
    if rows:
        t = Table(box=None, header_style="dim", padding=(0, 2), expand=True)
        t.add_column("", no_wrap=True)
        t.add_column("What", no_wrap=True)
        t.add_column("Times", justify="right")
        t.add_column("Latest", ratio=1, no_wrap=True, overflow="ellipsis")
        for title, sev, n, f in rows:
            t.add_row(Text(SEV_LABEL[sev], SEV_STYLE[sev]), Text(title, "bold" if sev == HIGH else ""), str(n),
                      Text.assemble((when(f.ts) + "  ", "dim"), one_line(short_path(f.detail), 80)))
        parts += [t, Text("")]
    else:
        parts += [Text("Nothing risky: no force-pushes, no curl | sh, no secrets, nothing outside your projects.",
                       "green"), Text("")]

    serious = sorted([f for f in a.findings if f.severity == HIGH], key=lambda f: -(f.ts or 0))[:show]
    if serious:
        g = Table(title="Most recent high-risk actions", title_justify="left", title_style="bold", box=None,
                  show_header=False, padding=(0, 2), expand=True)
        g.add_column(no_wrap=True, style="dim")
        g.add_column(no_wrap=True)
        g.add_column(no_wrap=True, style="dim")
        g.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        for f in serious:
            g.add_row(when(f.ts), AGENT_NAME.get(f.agent, f.agent), os.path.basename(f.project.rstrip("/\\")) or "?",
                      Text(one_line(short_path(f.detail), 90), "red"))
        parts += [g, Text("")]

    if a.top_commands:
        parts.append(Text("Most-run: " + ", ".join(f"{c} ({n})" for c, n in a.top_commands.most_common(8)), "dim"))
    console.print(Panel(Group(*parts), title="[bold]What did your AI agents do?[/]",
                        border_style="red" if any(f.severity == HIGH for f in a.findings) else "green", padding=(1, 2)))
    console.print(Text("  Share: ", "dim") + Text(a.share(), "italic"))
    console.print()


def parse_since(s: str) -> float | None:
    if s == "all":
        return None
    m = re.fullmatch(r"(\d+)\s*([hdwm])", s)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return time.time() - n * {"h": 3600, "d": 86400, "w": 7 * 86400, "m": 30 * 86400}[unit]
    from datetime import datetime
    try:
        return time.mktime(datetime.strptime(s, "%Y-%m-%d").timetuple())
    except ValueError:
        raise argparse.ArgumentTypeError("use e.g. 7d, 30d, 12h, 2026-10-01 or all")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentsnitch", description="See every command your AI coding agents ran and "
                                 "every file they touched, with the risky ones flagged. Reads Claude Code, Codex and "
                                 "Gemini CLI logs locally.")
    ap.add_argument("--since", type=parse_since, default=parse_since("30d"), help="7d, 30d (default), 12h, a date, or all")
    ap.add_argument("--project", help="only sessions whose folder contains this text")
    ap.add_argument("--agent", choices=["claude", "codex", "gemini"], help="only one agent")
    ap.add_argument("--low", action="store_true", help="also show low-severity findings")
    ap.add_argument("--log", action="store_true", help="print every command and file action, oldest first")
    ap.add_argument("--json", action="store_true", help="findings as JSON")
    ap.add_argument("-V", "--version", action="version", version=f"agentsnitch {__version__}")
    a = ap.parse_args(argv)
    console = Console(stderr=a.json)

    def keep(ev):
        return (not a.agent or ev.agent == a.agent) and (not a.project or a.project.lower() in (ev.cwd or "").lower())

    events = [ev for ev in agentlogs.all_events(since=a.since) if keep(ev)]
    if a.log:
        for ev in sorted(events, key=lambda e: e.ts or 0):
            if ev.kind in ("command", "read", "write", "edit", "fetch"):
                what = ev.command or ev.path or ev.text
                console.print(Text.assemble((time.strftime("%Y-%m-%d %H:%M", time.localtime(ev.ts or 0)) + "  ", "dim"),
                                            (f"{ev.agent:7} {ev.kind:7} ", "cyan"), one_line(short_path(what), 200)))
        return 0
    audit = run(events, a.since)
    if a.json:
        print(json.dumps({"since": a.since, "commands": audit.commands, "reads": audit.reads, "writes": audit.writes,
                          "sessions": len(audit.sessions), "highlights": audit.highlights(),
                          "findings": [asdict(f) for f in audit.findings],
                          "outside_writes": [asdict(f) for f in audit.outside_writes],
                          "outside_reads": [asdict(f) for f in audit.outside_reads]}, indent=2))
    else:
        render(audit, console, include_low=a.low)
    return 0


if __name__ == "__main__":
    sys.exit(main())
