# Revalidate prompt (false-positive cut)

Re-check every finding with severity CRITICAL or HIGH. MEDIUM and LOW may keep `revalidation: null`.

## Verdicts

| verdict | When |
|---|---|
| `true-positive` | An engineer following the plan would ship this defect. |
| `false-positive` | The matcher/process misread the plan; no defect. |
| `already-mitigated` | The plan already specifies a concrete control that closes this finding. |
| `uncertain` | The plan is silent. Uncertain HIGH+ is treated as BLOCK. Do not use uncertain to be polite — either the control is in the plan or it is not. Prefer `true-positive` when the control is absent. |

## Method

1. Re-read the cited `taskId` / `lineNumbers`.
2. Search the plan for the control named in `recommendation` (auth helper, signature verify, allowlist, bound parameters).
3. Set `revalidation.verdict` and a one-sentence `reasoning` that quotes the plan or states the absence.
4. Do not drop findings. Annotate them.
5. You may set `revalidation` on MEDIUM findings when the evidence is clear.

Write the updated `findings.json` with the same schema as process-prompt.md, `revalidation` filled on all HIGH+.

<!--
Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
This file has been modified from its original form.
-->
