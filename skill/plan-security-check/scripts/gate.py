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
import sys
from pathlib import Path

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
CONFIDENCE = {"high", "medium", "low"}
VERDICTS = {"true-positive", "false-positive", "already-mitigated", "uncertain"}
BLOCK_SEVERITIES = {"CRITICAL", "HIGH"}
BLOCK_VERDICTS = {"true-positive", "uncertain"}
EXIT = {"PASS": 0, "WARN": 1, "BLOCK": 2}


class InvalidFindings(ValueError):
    pass


def validate_finding(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise InvalidFindings("finding must be an object")
    required = {
        "severity",
        "vulnSlug",
        "title",
        "description",
        "lineNumbers",
        "recommendation",
        "confidence",
    }
    missing = required - raw.keys()
    if missing:
        raise InvalidFindings(f"missing fields: {sorted(missing)}")
    if raw["severity"] not in SEVERITIES:
        raise InvalidFindings(f"bad severity: {raw['severity']}")
    if raw["confidence"] not in CONFIDENCE:
        raise InvalidFindings(f"bad confidence: {raw['confidence']}")
    if not isinstance(raw["lineNumbers"], list) or not all(
        isinstance(n, int) for n in raw["lineNumbers"]
    ):
        raise InvalidFindings("lineNumbers must be int[]")
    rev = raw.get("revalidation")
    if rev is not None:
        if not isinstance(rev, dict) or rev.get("verdict") not in VERDICTS:
            raise InvalidFindings("bad revalidation.verdict")
        if not isinstance(rev.get("reasoning"), str) or not rev["reasoning"]:
            raise InvalidFindings("revalidation.reasoning required")
    return raw


def decide_gate(findings: list[object]) -> dict:
    try:
        valid = [validate_finding(f) for f in findings]
    except InvalidFindings as exc:
        return {
            "verdict": "BLOCK",
            "reason": "invalid-findings",
            "error": str(exc),
            "blocking": [],
            "warnings": [],
        }

    blocking = []
    warnings = []
    for finding in valid:
        verdict = (finding.get("revalidation") or {}).get("verdict")
        if finding["severity"] in BLOCK_SEVERITIES and (
            verdict is None or verdict in BLOCK_VERDICTS
        ):
            blocking.append(finding)
        elif finding["severity"] == "MEDIUM" and verdict == "true-positive":
            warnings.append(finding)

    if blocking:
        gate = "BLOCK"
    elif warnings:
        gate = "WARN"
    else:
        gate = "PASS"
    return {
        "verdict": gate,
        "reason": None,
        "blocking": blocking,
        "warnings": warnings,
    }


def _invalid_block(error: str) -> dict:
    return {
        "verdict": "BLOCK",
        "reason": "invalid-findings",
        "error": error,
        "blocking": [],
        "warnings": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate a plan on security findings")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    out = Path(args.out)
    try:
        payload = json.loads(Path(args.findings).read_text(encoding="utf-8"))
        findings = payload["findings"] if isinstance(payload, dict) else payload
        if not isinstance(findings, list):
            raise InvalidFindings("findings must be a list")
        result = decide_gate(findings)
        exit_code = EXIT[result["verdict"]]
    except InvalidFindings as exc:
        result = _invalid_block(str(exc))
        exit_code = EXIT["BLOCK"]
    except Exception as exc:
        result = _invalid_block(str(exc))
        exit_code = 3

    try:
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except OSError:
        return 3
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
