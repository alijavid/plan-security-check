---
name: plan-security-check
description: >-
  Runs a local security review of implementation plans before coding starts.
  Adapts a scan → process → revalidate → gate pipeline to plan markdown:
  regex matchers flag auth, injection, SSRF, secrets, and related surfaces;
  the current agent investigates; development is blocked on unmitigated HIGH+.
  Use when writing or reviewing implementation plans, after writing-plans,
  before executing a plan, or when the user asks for a plan security check,
  pre-dev security review, or /plan-security-check.
---

# Plan security check

Review the plan, not the application source. Stay local: use the coding agent already in this session. Do not call hosted scanners, cloud sandboxes, or vendor CLIs.

`SKILL_DIR` is the directory that contains this file.

## When to run

Run this skill:

1. After an implementation plan is written and before offering to execute or implement the plan.
2. When the user invokes `/plan-security-check` or asks to security-check a plan.
3. When the user is about to execute an existing plan that has no `## Security Check` section or whose verdict is stale (plan body changed after the section).

If the user asks to start coding and no PASS/WARN section exists, run this skill first.

## Workflow

Copy and track:

```
- [ ] 1. Resolve plan path
- [ ] 2. Scan
- [ ] 3. Process
- [ ] 4. Revalidate HIGH+
- [ ] 5. Gate
- [ ] 6. Write report into the plan
- [ ] 7. Stop on BLOCK or continue
```

### 1. Resolve plan path

Use the plan just written (typical: `docs/superpowers/plans/YYYY-MM-DD-<feature>.md`). If several exist, ask which one. Work from the repository root.

### 2. Scan

```bash
python3 "$SKILL_DIR/scripts/scan.py" \
  --plan "<ABS_PLAN>" \
  --out "<ABS_PLAN>.scan.json"
```

Read `<ABS_PLAN>.scan.json`. Candidates are anchors, not a whitelist.

### 3. Process (always-process)

Read [process-prompt.md](process-prompt.md) and [threat-classes.md](threat-classes.md). Inject per-tech highlights for `techTags`. If `SECURITY.md` exists at the repo root, read it.

Investigate the whole plan. Write `<ABS_PLAN>.findings.json` using the schema in process-prompt.md. `revalidation` is null at this step.

Docs-only plans with empty candidates still get this read; return `"findings": []` when there is no security surface.

### 4. Revalidate HIGH+

Read [revalidate-prompt.md](revalidate-prompt.md). Fill `revalidation` on every CRITICAL and HIGH finding. Rewrite `<ABS_PLAN>.findings.json`. Uncertain HIGH+ is BLOCK; prefer `true-positive` when the control is absent.

### 5. Gate

```bash
python3 "$SKILL_DIR/scripts/gate.py" \
  --findings "<ABS_PLAN>.findings.json" \
  --out "<ABS_PLAN>.gate.json"
```

Exit codes: `0` PASS, `1` WARN, `2` BLOCK, `3` error. Treat `3` as BLOCK.

### 6. Write the report

```bash
python3 "$SKILL_DIR/scripts/report.py" \
  --plan "<ABS_PLAN>" \
  --scan "<ABS_PLAN>.scan.json" \
  --findings "<ABS_PLAN>.findings.json" \
  --gate "<ABS_PLAN>.gate.json" \
  --in-place
```

### 7. Stop on BLOCK or continue

Delete `<ABS_PLAN>.scan.json`, `<ABS_PLAN>.findings.json`, and `<ABS_PLAN>.gate.json` after the report is written; the durable record is the plan section.

**BLOCK:** Do not offer plan execution. Patch the plan with the concrete controls from each blocking finding. Re-run from step 2. Repeat until PASS or WARN. Summarize what changed.

**WARN:** Show warnings. Offer execution only after the user acknowledges them.

**PASS:** Offer to execute the plan.

Never start implementation in the same turn as a BLOCK.

## Output to the user

Lead with the verdict. Then a compact table: Severity, Task, Finding. Do not dump raw JSON.

## References

- [threat-classes.md](threat-classes.md)
- [process-prompt.md](process-prompt.md)
- [revalidate-prompt.md](revalidate-prompt.md)
- [examples.md](examples.md)

<!--
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This file has been modified from its original form. See NOTICE.
-->
