# Plan security check

Security-review an implementation plan **before anyone writes the code**. Regex matchers flag risky language, the coding agent already in your session investigates the whole plan, and a local gate returns **PASS / WARN / BLOCK**. BLOCK means edit the plan and rerun. Do not start coding.

Works with any agent that can read a `SKILL.md` and run local Python: **Claude Code**, **ChatGPT Codex**, **Codex CLI**, **Cursor**, **Gemini CLI**, **GitHub Copilot**, and other Agent Skills hosts. No hosted scanner, no cloud sandbox, no extra API.

Licensed under the Apache License, Version 2.0. You may not use this project except in compliance with the License. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Why scan the plan, not the code

Coding agents implement the plan as written. If the plan adds `POST /api/invoices` and never names authentication, the agent will ship a public write endpoint. A code scanner can catch that later. By then the defect is already in the branch, the review, and often production.

Fixing it in the plan is a sentence: *require a session and an org-scoped authorization check before insert*. Fixing it after merge is a patch, a secret rotation, an incident write-up, and every client that already called the open route.

This skill is a pre-dev gate:

- It reviews **intent** (what you are about to build), not a snapshot of files that do not exist yet.
- It fails closed. Missing findings, invalid JSON, or an unmitigated HIGH/CRITICAL finding is **BLOCK**.
- The verdict is appended to the plan, so the next session cannot “just start coding” past an unresolved BLOCK.
- Matcher hits are anchors, not a whitelist. Docs-only plans still get a full read; they PASS when there is no security surface.

Use it after the plan is written and before execution. That is the cheapest moment a vulnerability will ever be.

## What it checks

The scanner looks for security-relevant language in plan markdown. The agent then asks whether the plan names a concrete control. “We will think about auth later” is not a control.

| Check | What a passing plan must name |
|---|---|
| Auth boundary | Authn and authz on every new HTTP, RPC, webhook, or server-action ingress — who can act on whose data |
| SQL injection | Bound parameters; no f-string / concatenated / raw SQL |
| SSRF | Server-side fetches allowlist scheme and host; no user-controlled URLs |
| Path traversal | Uploads land in a fixed directory with generated names; user path segments are not joined |
| XSS | User HTML/Markdown is sanitized or not rendered as HTML |
| Secrets | Credentials in env vars, never in source, client bundles, or committed `.env` |
| Command injection | No shell. If a binary must run, argv is a literal list |
| Insecure deserialization | No `pickle.loads` / `yaml.load` / `unserialize` on untrusted bytes |
| CORS | Credentialed APIs name explicit origins; no `*` |
| Webhooks | Inbound webhooks verify provider signatures before mutations |
| Mass assignment | Persistence allowlists fields; request bodies are not spread into updates |
| Weak crypto | Passwords use argon2/bcrypt/scrypt; JWT algorithms are explicit and exclude `none` |
| Agent tool egress | Agent tools cannot exec arbitrary shell or fetch arbitrary URLs |
| CI untrusted checkout | Jobs that run pull-request code do not get `write` or secrets |

Per-tech notes cover Next.js (middleware is not auth for Server Actions), Express, FastAPI, Django, Rails, Go, GitHub Actions, and agent tool schemas. If a repo-root `SECURITY.md` exists, that is read too.

**BLOCK** — unmitigated HIGH or CRITICAL (missing authz on a new write route, unverified webhook that mutates, PR CI with secrets). Edit the plan, rerun.  
**WARN** — lower-severity issues. Acknowledge before executing.  
**PASS** — no unmitigated HIGH+, or a docs-only plan with no security surface.

## Install

Requires **Python 3.11+** (stdlib only at runtime). The agent must have a local shell so it can run `scripts/scan.py`, `gate.py`, and `report.py`. Browser-only ChatGPT without a connected workspace cannot run the gate.

```bash
git clone https://github.com/alijavid/plan-security-check.git
cd plan-security-check
python3 -m pytest
```

Symlink the skill directory into the agent you use. The folder includes its own `LICENSE` and `NOTICE`.

```bash
SKILL="$(pwd)/skill/plan-security-check"

# Claude Code
ln -sfn "$SKILL" "$HOME/.claude/skills/plan-security-check"

# ChatGPT Codex / Codex CLI
ln -sfn "$SKILL" "$HOME/.agents/skills/plan-security-check"

# Cursor
ln -sfn "$SKILL" "$HOME/.cursor/skills/plan-security-check"

# Gemini CLI
ln -sfn "$SKILL" "$HOME/.gemini/skills/plan-security-check"

# GitHub Copilot
ln -sfn "$SKILL" "$HOME/.copilot/skills/plan-security-check"
```

To share it with a repo instead of installing globally, symlink into the project skill dir (`.claude/skills/`, `.agents/skills/`, or `.cursor/skills/`). Restart the agent if it does not appear.

Do not put it in `~/.cursor/skills-cursor/` (Cursor built-ins). Confirm the skill is visible as `plan-security-check`.

## Use

After an implementation plan is written, before executing it:

```
/plan-security-check
```

Or ask the agent to run a plan security check on the plan file. Typical plan path: `docs/superpowers/plans/YYYY-MM-DD-<feature>.md`.

The agent scans, investigates, revalidates HIGH+ findings, gates, and writes a `## Security Check` section into the plan. On BLOCK it must not offer to start implementation.

## Layout

Runtime files live in `skill/plan-security-check/`. Tests live in `tests/`. pytest is the only development dependency.
