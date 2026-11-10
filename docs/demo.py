"""Write a month of made-up Claude Code, Codex and Gemini CLI logs to a temp home folder and run agentsnitch on it.
Used to record the README GIF; none of this is real activity."""
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

random.seed(4)
HOME = Path(tempfile.mkdtemp(prefix="agentsnitch-demo-"))
NOW = time.time()
U = "/Users/sam"
PROJECTS = [f"{U}/code/storefront", f"{U}/code/pricing-api", f"{U}/code/ml-pipeline", f"{U}/code/dotfiles"]
ROUTINE = ["npm test", "npm run build", "npm run lint -- --fix", "pytest -q", "pytest tests/test_api.py -x",
           "git status", "git diff --stat", "git log --oneline -10", "git add -A", "git commit -m 'wip'",
           "rg -n TODO src", "ls -la", "cat package.json", "python -m mypy src", "uv run pytest",
           "docker compose up -d db", "npx prisma migrate dev", "go test ./...", "cargo check", "make test",
           "rm -rf node_modules/.cache", "git checkout -b fix/cart-total", "git push -u origin HEAD"]
SPICY = [  # (command, probability per session)
    ("curl -fsSL https://bun.sh/install | bash", 0.06),
    ("git push --force origin main", 0.03),
    ("cat ~/.ssh/id_ed25519", 0.015),
    ("cat .env.production", 0.05),
    ("printenv | grep -i key", 0.03),
    ("sudo chown -R $(whoami) /usr/local/lib/node_modules", 0.03),
    ("git reset --hard origin/main", 0.05),
    ("echo 'export PATH=$HOME/.bun/bin:$PATH' >> ~/.zshrc", 0.03),
    ("aws s3 rm s3://pricing-api-staging --recursive", 0.01),
    ("npm publish --access public", 0.01),
]


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t))


sessions = 0
for day in range(30):
    for _ in range(random.randint(2, 5)):
        sessions += 1
        agent = random.choices(["claude", "codex", "gemini"], [0.62, 0.28, 0.10])[0]
        proj = random.choice(PROJECTS)
        t = NOW - day * 86400 - random.randint(0, 40000)
        cmds = [random.choice(ROUTINE) for _ in range(random.randint(8, 30))]
        cmds += [c for c, p in SPICY if random.random() < p]
        random.shuffle(cmds)
        files = [("write", f"{proj}/src/{random.choice(['cart', 'api', 'utils', 'models'])}.ts")
                 for _ in range(random.randint(2, 8))]
        if random.random() < 0.08:
            files.append(("write", f"{U}/.config/git/ignore"))
        if random.random() < 0.02:
            files.append(("read", f"{U}/.aws/credentials"))
        steps = [("command", c) for c in cmds] + files
        sid = f"s{sessions}"
        if agent == "claude":
            d = HOME / ".claude" / "projects" / proj.replace("/", "-")
            d.mkdir(parents=True, exist_ok=True)
            with (d / f"{sid}.jsonl").open("a") as fh:
                for i, (kind, what) in enumerate(steps):
                    name, inp = ("Bash", {"command": what}) if kind == "command" else \
                        ("Write", {"file_path": what, "content": "x"}) if kind == "write" else ("Read", {"file_path": what})
                    fh.write(json.dumps({"type": "assistant", "timestamp": iso(t + i * 20), "cwd": proj, "sessionId": sid,
                                         "message": {"content": [{"type": "tool_use", "name": name, "input": inp}]}}) + "\n")
        elif agent == "codex":
            d = HOME / ".codex" / "sessions" / "2026" / "11" / f"{day:02d}"
            d.mkdir(parents=True, exist_ok=True)
            lines = [{"timestamp": iso(t), "type": "session_meta", "payload": {"id": sid, "cwd": proj}}]
            for i, (kind, what) in enumerate(steps):
                if kind == "command":
                    p = {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"cmd": what})}
                else:
                    p = {"type": "custom_tool_call", "name": "apply_patch",
                         "input": f"*** Begin Patch\n*** Update File: {what}\n+x\n*** End Patch\n"}
                lines.append({"timestamp": iso(t + i * 20), "type": "response_item", "payload": p})
            (d / f"rollout-{sid}.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n")
        else:
            d = HOME / ".gemini" / "tmp" / proj.rsplit("/", 1)[1] / "chats"
            d.mkdir(parents=True, exist_ok=True)
            calls = [{"id": str(i), "name": "run_shell_command" if k == "command" else "write_file" if k == "write"
                      else "read_file", "args": {"command": w} if k == "command" else {"file_path": w, "content": "x"},
                      "timestamp": iso(t + i * 20)} for i, (k, w) in enumerate(steps)]
            (d / f"session-{sid}.jsonl").write_text(json.dumps({"sessionId": sid, "projectHash": "h"}) + "\n" +
                                                     json.dumps({"id": "m", "type": "gemini", "timestamp": iso(t),
                                                                 "content": "", "toolCalls": calls}) + "\n")
(HOME / ".gemini" / "projects.json").write_text(json.dumps({"projects": {p: p.rsplit("/", 1)[1] for p in PROJECTS}}))
env = dict(os.environ, HOME=str(HOME), USERPROFILE=str(HOME))
env.pop("CLAUDE_CONFIG_DIR", None)
env.pop("CODEX_HOME", None)
sys.exit(subprocess.call(["agentsnitch"], env=env))
