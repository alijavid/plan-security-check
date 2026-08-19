# Process prompt (plan investigation)

You are investigating an implementation plan for security defects that would be introduced if an engineer followed the plan as written. You are not scanning the application repo the way a code scanner would.

## Always-process

Read the entire plan, including tasks with zero matcher hits. Candidates are prompt anchors, not a whitelist. This is the Deepsec direct-mode rule: listed inputs are always investigated.

## Inputs

- Plan markdown
- `scan.json` (`techTags`, `candidates`)
- `threat-classes.md` (read the always-on table plus any matching per-tech highlights)
- Optional repo `SECURITY.md` if it exists at the repository root; skip if absent

## Rules

- Flag only issues that would cause a real vulnerability or missing control in the resulting software.
- If the plan already names a concrete control (function, library, check), do not invent a finding.
- Missing authz on a new write endpoint is HIGH or CRITICAL, not a nit.
- Docs-only / typo plans with no ingress, no data, no CI secrets: return `"findings": []`.
- Do not recommend hosted scanners, cloud sandboxes, or vendor CLIs. Stay on the current agent and the scripts in this skill.

## Output

Write `findings.json` next to the plan (or to the path given by the runbook) with only this shape:

```json
{
  "findings": [
    {
      "severity": "HIGH",
      "vulnSlug": "auth-boundary",
      "title": "Public invoice POST has no authentication",
      "description": "Task 1 adds POST /api/invoices and never names a session or org check.",
      "taskId": "1",
      "lineNumbers": [12],
      "recommendation": "Require a session and `invoice.orgId === session.orgId` before insert.",
      "confidence": "high",
      "revalidation": null
    }
  ]
}
```

Leave `revalidation` null here. The revalidate step fills it.

<!--
Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
This file has been modified from its original form.
-->
