# Examples

## BLOCK — public API with no auth

Input: `tests/fixtures/plans/vulnerable-public-api.md`

Scan hits: `auth-boundary`, `webhook-unverified`, `ssrf`.

Process finding:

```json
{
  "severity": "HIGH",
  "vulnSlug": "auth-boundary",
  "title": "POST /api/invoices is public",
  "description": "Task 1 adds the endpoint and never names authentication.",
  "taskId": "1",
  "lineNumbers": [12],
  "recommendation": "Require a session and org-scoped authorization before insert.",
  "confidence": "high",
  "revalidation": {
    "verdict": "true-positive",
    "reasoning": "The plan never mentions auth, session, or orgId checks."
  }
}
```

Gate: BLOCK. Agent must edit the plan, then rescan, and must not offer execution.

## PASS — same feature, controls named

Input: `tests/fixtures/plans/mitigated-public-api.md`

Scan still hits `auth-boundary` and `webhook-unverified` (noisy/normal entry points). Process may emit findings; revalidate marks them `already-mitigated` because the plan requires a session, org check, and `constructEvent`. Gate: PASS.

## PASS — docs-only

Input: `tests/fixtures/plans/docs-only.md`

Scan: no precise hits. Process: `"findings": []`. Gate: PASS.

<!--
Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
This file has been modified from its original form.
-->
