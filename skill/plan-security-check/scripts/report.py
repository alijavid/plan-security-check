# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file has been modified from its original form. See the NOTICE
# file distributed with this work for third-party attribution.

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SECTION_RE = re.compile(
    r"^## Security Check\n.*?(?=^## |\Z)",
    re.MULTILINE | re.DOTALL,
)


def render_section(gate: dict, findings: list[dict], candidates: list[dict]) -> str:
    lines = [
        "## Security Check",
        "",
        f"**Verdict:** {gate['verdict']}",
        "",
        "Local plan review (scan → process → revalidate → gate). Development must not start on BLOCK.",
        "",
        "### Candidates",
        "",
    ]
    if not candidates:
        lines.append("- None")
    else:
        for candidate in candidates:
            lines.append(
                f"- `{candidate['vulnSlug']}` lines {candidate['lineNumbers']}: {candidate.get('snippet', '')}"
            )
    lines.extend(["", "### Findings", ""])
    if not findings:
        lines.append("- None")
    else:
        for finding in findings:
            verdict = (finding.get("revalidation") or {}).get("verdict", "unreviewed")
            lines.append(
                f"- **{finding['severity']}** `{finding['vulnSlug']}` ({verdict}): {finding['title']}"
            )
            lines.append(f"  - {finding['recommendation']}")
    lines.extend(
        [
            "",
            "### Gate",
            "",
            f"- Blocking: {len(gate.get('blocking') or [])}",
            f"- Warnings: {len(gate.get('warnings') or [])}",
            "",
        ]
    )
    return "\n".join(lines)


def upsert_report(plan_text: str, section: str) -> str:
    body = section if section.endswith("\n") else section + "\n"
    if SECTION_RE.search(plan_text):
        return SECTION_RE.sub(lambda _match: body, plan_text, count=1)
    text = plan_text if plan_text.endswith("\n") else plan_text + "\n"
    return text + "\n" + body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a Security Check section into a plan")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--scan", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--in-place", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    if not args.in_place and not args.out:
        parser.error("--out is required unless --in-place is set")

    plan_path = Path(args.plan)
    scan = json.loads(Path(args.scan).read_text(encoding="utf-8"))
    findings_doc = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    gate = json.loads(Path(args.gate).read_text(encoding="utf-8"))
    findings = findings_doc["findings"] if isinstance(findings_doc, dict) else findings_doc
    section = render_section(gate, findings, scan.get("candidates", []))
    updated = upsert_report(plan_path.read_text(encoding="utf-8"), section)
    dest = plan_path if args.in_place else Path(args.out)
    dest.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
