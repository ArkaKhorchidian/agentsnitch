"""What counts as risky when an AI agent runs it on your machine."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass(frozen=True)
class Rule:
    key: str
    title: str  # short, for tables
    severity: str
    pattern: re.Pattern
    why: str


def R(key, title, severity, pattern, why):
    return Rule(key, title, severity, re.compile(pattern, re.I | re.M), why)


# Patterns match anywhere in the command line, including inside `bash -c "..."` and pipelines.
COMMAND_RULES = [
    # --- remote code ---------------------------------------------------------------------------------
    R("pipe-to-shell", "Piped a download into a shell", HIGH,
      r"(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|"
      r"\|\s*(sudo\s+)?python3?\b\s*(-\s*)?$|\b(iex|invoke-expression)\b",
      "runs whatever that URL serves, unread"),
    R("eval-remote", "eval'd a download", HIGH, r"\beval\s+[\"']?\$\((curl|wget)", "runs whatever that URL serves"),
    # --- destruction ----------------------------------------------------------------------------------
    R("rm-root", "rm -rf on home or root", HIGH,
      r"\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive\s+--force|-r\s+-f|-f\s+-r)\s+"
      r"(\"?(~|\$home|/|/\*|\.\.)\"?/?(\s|$))",
      "one typo away from deleting everything"),
    R("rm-rf", "rm -rf", LOW,
      r"\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive\s+--force|-r\s+-f|-f\s+-r)\b",
      "recursive force delete"),
    R("force-push", "Force-pushed", HIGH, r"\bgit\b[^;&|]*\bpush\b[^;&|]*(\s--force\b|\s-f\b|\s--force-with-lease\b|\s\+\S)",
      "rewrites shared history on the remote"),
    R("reset-hard", "git reset --hard / clean", MEDIUM, r"\bgit\b[^;&|]*\b(reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s+\.|"
      r"restore\s+(--staged\s+)?\.(\s|$)|stash\s+(drop|clear))",
      "throws away uncommitted work"),
    R("drop-db", "Dropped or wiped a database", HIGH, r"\b(drop\s+(table|database|schema)|truncate\s+table|dropdb\b|"
      r"flushall\b|flushdb\b|db\.dropDatabase)", "data loss"),
    R("disk", "Low-level disk command", HIGH, r"\b(mkfs(\.\w+)?|dd\s+[^|;&]*\bof=/dev/|diskutil\s+(erase|partition)|"
      r"fdisk|parted)\b", "can wipe a disk"),
    R("infra-destroy", "Destroyed infrastructure", HIGH, r"\b(terraform\s+destroy|kubectl\s+delete|helm\s+uninstall|"
      r"aws\s+\S+\s+(delete|terminate|rm)\S*|gcloud\s+.*\bdelete\b|docker\s+(system\s+prune|volume\s+rm|rm\s+-f))",
      "deletes real resources"),
    R("chmod-777", "chmod 777", MEDIUM, r"\bchmod\s+(-R\s+)?(0?777|a\+rwx)\b", "makes files writable by anyone"),
    # --- secrets --------------------------------------------------------------------------------------
    R("ssh-keys", "Touched SSH keys", HIGH, r"\.ssh/(id_[\w-]+|identity|[\w.-]*_(rsa|ed25519|ecdsa|dsa)|[\w.-]+\.pem)"
      r"(?!\.pub)\b(?!\.pub)", "private keys"),
    R("cloud-creds", "Read cloud credentials", HIGH, r"\.aws/credentials|\.config/gcloud/(credentials|application_default)|"
      r"\.azure/|\.kube/config|\.docker/config\.json|\.netrc|\.npmrc|\.pypirc|\.git-credentials", "credentials"),
    R("keychain", "Read the keychain / password store", HIGH, r"\bsecurity\s+(find|dump)-(generic|internet)-password|"
      r"\bsecret-tool\s+lookup|\bpass\s+show\b|\bop\s+(read|item\s+get)\b|\bgh\s+auth\s+token\b|cmdkey\s+/list",
      "pulls secrets out of your password store"),
    R("dotenv", "Read a .env file", MEDIUM, r"(^|[\s/'\"])\.env(\.\w+)?\b(?!\.example|\.sample|\.template)",
      "usually holds API keys"),
    R("env-dump", "Dumped all environment variables", MEDIUM, r"(^|[;&|]\s*)(printenv|env|set|export\s+-p)\s*($|[|>;&])",
      "prints every secret in your environment"),
    # --- sending things out -------------------------------------------------------------------------
    R("upload", "Sent data to a server", MEDIUM, r"\bcurl\b(?![^|;&]*\s(-G|--get)\b)[^|;&]*(\s-d\s|\s--data(-binary|-raw|-urlencode)?\b|\s-F\s|"
      r"\s--form\b|\s-T\s|\s--upload-file\b|\s-X\s*(POST|PUT|PATCH)\b)|\bwget\b[^|;&]*--post-(data|file)|"
      r"\b(nc|ncat|netcat|socat)\b\s+\S+\s+\d+", "data leaving your machine"),
    R("remote-copy", "Copied files to another machine", MEDIUM, r"\b(scp|rsync|sftp)\b[^|;&]*\S+@?[\w.-]+:", "files leaving"),
    R("ssh", "SSH'd somewhere", LOW, r"(^|[;&|]\s*)ssh\s+(-\S+\s+)*[\w.-]*@?[\w.-]+\.\w+", "remote access"),
    # --- shipping / irreversible ---------------------------------------------------------------------
    R("publish", "Published a package", HIGH, r"\b(npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\b(uv|poetry|flit|hatch)"
      r"\s+publish\b|\bcargo\s+publish\b|\bgem\s+push\b|\bdocker\s+push\b|\bgh\s+release\s+create\b",
      "ships to the world, can't unship"),
    R("push", "git push", LOW, r"\bgit\b[^;&|]*\bpush\b", "changes the remote"),
    R("merge-pr", "Merged a PR", MEDIUM, r"\bgh\s+pr\s+merge\b", "lands code on someone's main branch"),
    R("deploy", "Deployed", MEDIUM, r"\b(vercel\s+(--prod|deploy)|netlify\s+deploy|fly\s+deploy|kubectl\s+apply|"
      r"terraform\s+apply|serverless\s+deploy|firebase\s+deploy|wrangler\s+(deploy|publish))\b", "changes production"),
    # --- your system --------------------------------------------------------------------------------
    R("sudo", "Used sudo", MEDIUM, r"(^|[;&|]\s*|\s)sudo\s", "root on your machine"),
    R("persistence", "Set up something that runs on its own", MEDIUM, r"\b(crontab\s+(-e|-|\S+\.txt)|launchctl\s+(load|"
      r"bootstrap)|systemctl\s+(--user\s+)?enable|schtasks\s+/create)\b|Library/LaunchAgents", "keeps running later"),
    R("shell-rc", "Edited your shell startup files", MEDIUM, r"(>>?|tee(\s+-a)?)\s*\S*(\.zshrc|\.bashrc|\.bash_profile|"
      r"\.profile|\.zprofile|config\.fish)\b", "runs in every terminal you open"),
    R("global-install", "Installed software", LOW, r"\b(npm|pnpm|yarn)\s+(i|install|add)\s+(-g|--global)\b|"
      r"\bbrew\s+install\b|\bapt(-get)?\s+install\b|\bpip3?\s+install\b(?![^;&|]*(-r\s|--requirement|-e\s|\.))",
      "new software outside the project"),
    R("kill", "Killed processes broadly", LOW, r"\b(pkill|killall)\b|\bkill\s+-9\s+-1\b", "can take down other apps"),
]

SENSITIVE_PATHS = [
    (re.compile(r"/\.ssh/(?!.*\.pub$)(?!known_hosts|config$|authorized_keys)"), "ssh-keys", "Touched SSH keys", HIGH),
    (re.compile(r"/\.aws/|/\.config/gcloud/|/\.azure/|/\.kube/config|/\.docker/config\.json|/\.netrc$|/\.npmrc$|"
                r"/\.pypirc$|/\.git-credentials$"), "cloud-creds", "Read cloud credentials", HIGH),
    (re.compile(r"(^|/)\.env(\.[\w-]+)?$"), "dotenv", "Read a .env file", MEDIUM),
    (re.compile(r"/(Library/Keychains|\.gnupg|\.password-store)/"), "keychain", "Read the keychain / password store", HIGH),
    (re.compile(r"/(\.zshrc|\.bashrc|\.bash_profile|\.profile|\.zprofile)$"), "shell-rc",
     "Edited your shell startup files", MEDIUM),
]
DOTENV_OK = re.compile(r"\.env\.(example|sample|template|dist)$")


HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2\s*(\n|$)", re.S)
INLINE_SCRIPT = re.compile(r"\b(python[\d.]*|node|ruby|perl|php|deno\s+eval)\s+(-[a-zA-Z]*\s+)*-[ce]\s+"
                           r"(\"(\\.|[^\"\\])*\"|'[^']*')", re.S)


def shell_only(cmd: str) -> str:
    """Drop heredoc bodies and inline Python/Node scripts: their text isn't run by the shell, so a test file that
    mentions `curl | sh` shouldn't count as running it. (bash -c "..." stays: that IS shell.)"""
    cmd = HEREDOC.sub(lambda m: m.group(0).split("\n", 1)[0] + "\n", cmd)
    return INLINE_SCRIPT.sub(lambda m: m.group(1) + " -c …", cmd)


def classify_command(cmd: str) -> list[tuple[Rule, str]]:
    """[(rule, the part of the command that matched)]"""
    cmd = shell_only(cmd)
    hits: list[tuple[Rule, str]] = []
    keys = set()
    for r in COMMAND_RULES:
        m = r.pattern.search(cmd)
        if m:
            # a specific rule hides its generic cousin
            if r.key == "rm-rf" and "rm-root" in keys or r.key == "push" and "force-push" in keys:
                continue
            a, b = max(0, m.start() - 25), min(len(cmd), m.end() + 35)
            snippet = ("…" if a else "") + cmd[a:b].strip() + ("…" if b < len(cmd) else "")
            hits.append((r, snippet))
            keys.add(r.key)
    return hits


def classify_path(path: str, kind: str) -> list[tuple[str, str, str]]:
    p = path.replace("\\", "/")
    out = []
    for rx, key, title, sev in SENSITIVE_PATHS:
        if rx.search(p) and not (key == "dotenv" and DOTENV_OK.search(p)):
            if key == "shell-rc" and kind not in ("write", "edit"):
                continue
            out.append((key, title, sev))
    return out


def _norm(path: str) -> str:
    p = path.replace("\\", "/")
    p = re.sub(r"/+", "/", p)
    parts: list[str] = []
    for seg in p.split("/"):
        if seg == "..":
            if parts and parts[-1] not in ("", ".."):
                parts.pop()
        elif seg != ".":
            parts.append(seg)
    out = "/".join(parts)
    return out.lower() if re.match(r"^[a-z]:", out, re.I) else out


TEMP = re.compile(r"^(/tmp|/private/tmp|/var/folders|/private/var/folders|/dev/null)(/|$)|/temp/|/appdata/local/temp/",
                  re.I)


def outside(path: str, project: str | None) -> bool:
    """Did the agent touch a file outside the folder it was started in? (Temp folders don't count.)"""
    if not project or not path:
        return False
    p = _norm(path)
    if not (p.startswith("/") or re.match(r"^[a-z]:/", p)):
        return False  # relative paths are inside the project
    root = _norm(project).rstrip("/")
    if p == root or p.startswith(root + "/"):
        return False
    return not TEMP.search(p)
