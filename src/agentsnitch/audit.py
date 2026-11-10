"""Go through everything your agents did and pull out what deserves a second look."""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .agentlogs import Event
from .rules import HIGH, LOW, MEDIUM, classify_command, classify_path, outside

ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


@dataclass
class Finding:
    key: str
    title: str
    severity: str
    agent: str
    project: str
    ts: float | None
    detail: str  # the matching part of the command, or the file path
    session: str
    command: str = ""  # the whole command


@dataclass
class Audit:
    since: float | None
    commands: int = 0
    reads: int = 0
    writes: int = 0
    fetches: int = 0
    prompts: int = 0
    sessions: set = field(default_factory=set)
    projects: Counter = field(default_factory=Counter)
    agents: Counter = field(default_factory=Counter)  # agent -> actions
    top_commands: Counter = field(default_factory=Counter)  # first word of each command
    findings: list[Finding] = field(default_factory=list)
    outside_writes: list[Finding] = field(default_factory=list)
    outside_reads: list[Finding] = field(default_factory=list)

    @property
    def actions(self) -> int:
        return self.commands + self.reads + self.writes + self.fetches

    def by_rule(self) -> list[tuple[str, str, int, Finding]]:
        """(title, severity, count, most recent example), most serious first."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            groups[f.key].append(f)
        out = []
        for key, fs in groups.items():
            fs.sort(key=lambda f: f.ts or 0)
            out.append((fs[-1].title, fs[-1].severity, len(fs), fs[-1]))
        if self.outside_writes:
            fs = sorted(self.outside_writes, key=lambda f: f.ts or 0)
            out.append(("Wrote files outside the project", MEDIUM, len(fs), fs[-1]))
        if self.outside_reads:
            fs = sorted(self.outside_reads, key=lambda f: f.ts or 0)
            out.append(("Read files outside the project", LOW, len(fs), fs[-1]))
        return sorted(out, key=lambda x: (ORDER[x[1]], -x[2]))

    def count(self, key: str) -> int:
        return sum(1 for f in self.findings if f.key == key)

    def highlights(self) -> list[str]:
        """The few facts worth putting in a screenshot."""
        h = []
        for key, one, many in [("force-push", "force-push", "force-pushes"),
                               ("pipe-to-shell", "curl | sh", "curl | sh runs"),
                               ("rm-root", "rm -rf on your home folder", "rm -rf runs on your home folder"),
                               ("ssh-keys", "SSH key access", "SSH key accesses"),
                               ("cloud-creds", "cloud credential read", "cloud credential reads"),
                               ("keychain", "password-store read", "password-store reads"),
                               ("dotenv", ".env read", ".env reads"),
                               ("publish", "package publish", "package publishes"),
                               ("drop-db", "dropped database", "dropped databases"),
                               ("sudo", "sudo", "sudos")]:
            n = self.count(key)
            if n:
                h.append(f"{n} {one if n == 1 else many}")
        if self.outside_writes:
            n = len({f.detail for f in self.outside_writes})
            h.append(f"{n} file{'s' * (n != 1)} written outside the project")
        return h

    def period(self) -> str:
        import time
        if not self.since:
            return "so far"
        days = round((time.time() - self.since) / 86400)
        return "today" if days <= 1 else f"in the last {days} days"

    def share(self) -> str:
        bits = self.highlights()[:3]
        s = f"My AI coding agents ran {self.commands:,} commands {self.period()}"
        s += (": " + ", ".join(bits)) if bits else ", and nothing scary"
        return s + ". What did yours do? uvx agentsnitch"


SKIP = {"cd", "export", "set", "source", ".", "for", "do", "done", "if", "then", "fi", "else", "while", "echo",
        "true", "false", "sleep", "time", "env", "exec", "(", "{", "}", "then", "local"}


def programs(cmd: str) -> list[str]:
    """The programs a command line runs: `cd x && npm test | tee log` -> ["npm", "tee"]."""
    import re
    from .rules import shell_only
    out = []
    for seg in re.split(r"&&|\|\||[;|\n]", shell_only(cmd)):
        words = [w for w in seg.strip().split() if not re.match(r"^\w+=", w)]
        if words and words[0] not in SKIP and re.match(r"^[\w./-]+$", words[0]):
            out.append(os.path.basename(words[0]))
    return out


def project_of(ev: Event) -> str:
    return ev.cwd or "?"


def run(events, since: float | None = None) -> Audit:
    a = Audit(since)
    roots: dict[tuple[str, str], str] = {}  # each session's project = the folder the agent was started in
    for ev in events:
        a.agents[ev.agent] += ev.kind != "prompt"
        a.sessions.add((ev.agent, ev.session))
        if ev.cwd:
            roots.setdefault((ev.agent, ev.session), ev.cwd)
        proj = roots.get((ev.agent, ev.session)) or project_of(ev)
        if ev.kind == "prompt":
            a.prompts += 1
            continue
        if ev.kind not in ("command", "read", "write", "edit", "fetch"):
            continue
        a.projects[proj] += 1
        if ev.kind == "command":
            a.commands += 1
            for prog in programs(ev.command):
                a.top_commands[prog] += 1
            for r, snippet in classify_command(ev.command):
                a.findings.append(Finding(r.key, r.title, r.severity, ev.agent, proj, ev.ts, snippet, ev.session,
                                          ev.command))
        elif ev.kind == "fetch":
            a.fetches += 1
        else:
            if ev.kind == "read":
                a.reads += 1
            else:
                a.writes += 1
            for key, title, sev in classify_path(ev.path, ev.kind):
                a.findings.append(Finding(key, title, sev, ev.agent, proj, ev.ts, ev.path, ev.session))
            path = ev.path if os.path.isabs(ev.path) or not ev.cwd else os.path.join(ev.cwd, ev.path)
            if outside(path, proj if proj != "?" else None):
                f = Finding("outside", "", MEDIUM if ev.kind != "read" else LOW, ev.agent, proj, ev.ts, ev.path,
                            ev.session)
                (a.outside_reads if ev.kind == "read" else a.outside_writes).append(f)
    return a
