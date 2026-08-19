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
from dataclasses import dataclass, field
from pathlib import Path

ALLOWED_FLAGS = {"i", "m", "im"}
FORBIDDEN_REGEX = re.compile(r"\(\?\<|[\\][1-9]|\(\.\+\)\+|\(\.\*\)\+")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


@dataclass(frozen=True)
class Candidate:
    vuln_slug: str
    line_numbers: list[int]
    snippet: str
    matched_pattern: str
    noise_tier: str


@dataclass
class ScanResult:
    plan_path: str
    tech_tags: list[str] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)


def candidate_to_dict(candidate: Candidate) -> dict:
    return {
        "vulnSlug": candidate.vuln_slug,
        "lineNumbers": list(candidate.line_numbers),
        "snippet": candidate.snippet,
        "matchedPattern": candidate.matched_pattern,
        "noiseTier": candidate.noise_tier,
    }


def scan_result_to_dict(result: ScanResult) -> dict:
    return {
        "planPath": result.plan_path,
        "techTags": list(result.tech_tags),
        "candidates": [candidate_to_dict(c) for c in result.candidates],
    }


def load_matchers(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "matchers" not in data:
        raise ValueError("matchers.json must be an object with a matchers array")
    matchers = data["matchers"]
    if not isinstance(matchers, list):
        raise ValueError("matchers.json must be an object with a matchers array")
    slugs: set[str] = set()
    for spec in matchers:
        validate_matcher(spec)
        if spec["slug"] in slugs:
            raise ValueError(f"duplicate matcher slug: {spec['slug']}")
        slugs.add(spec["slug"])
    return matchers


def validate_matcher(spec: dict) -> None:
    required = {"slug", "description", "noiseTier", "cwe", "patterns", "examples"}
    missing = required - spec.keys()
    if missing:
        raise ValueError(f"matcher missing fields: {sorted(missing)}")
    if not SLUG_RE.match(spec["slug"]):
        raise ValueError(f"invalid slug: {spec['slug']}")
    if spec["noiseTier"] not in {"precise", "normal", "noisy"}:
        raise ValueError(f"{spec['slug']}: bad noiseTier")
    if not spec["patterns"] or not spec["examples"]:
        raise ValueError(f"{spec['slug']}: patterns and examples are required")
    for pattern in spec["patterns"]:
        flags = pattern.get("flags", "i")
        if flags not in ALLOWED_FLAGS:
            raise ValueError(f"{spec['slug']}: flags must be i, m, or im")
        regex = pattern["regex"]
        if not regex or FORBIDDEN_REGEX.search(regex):
            raise ValueError(f"{spec['slug']}: unsafe regex {regex!r}")
        re.compile(regex, _flags(flags))


def _flags(raw: str) -> int:
    value = 0
    if "i" in raw:
        value |= re.IGNORECASE
    if "m" in raw:
        value |= re.MULTILINE
    return value


TECH_NEEDLES: list[tuple[str, tuple[str, ...]]] = [
    ("nextjs", (r"next\.js", r"nextjs")),
    ("express", (r"\bexpress\b",)),
    ("fastapi", (r"\bfastapi\b",)),
    ("django", (r"\bdjango\b",)),
    ("rails", (r"\brails\b",)),
    ("go", (r"go\.mod", r"gin-gonic", r"chi router", r"labstack/echo", r"gofiber")),
    ("github-actions", (r"github actions", r"\.github/workflows")),
    ("agent", (r"agent tool", r"\bmcp\b", r"tool call")),
]

SNIPPET_MAX = 160


def detect_tech(text: str) -> list[str]:
    tags: list[str] = []
    for tag, needles in TECH_NEEDLES:
        if any(re.search(needle, text, flags=re.IGNORECASE) for needle in needles):
            tags.append(tag)
    return tags


def scan_plan(text: str, plan_path: str, matchers: list[dict]) -> ScanResult:
    lines = text.splitlines()
    candidates: list[Candidate] = []
    for spec in matchers:
        compiled = [
            (
                re.compile(p["regex"], _flags(p.get("flags", "i"))),
                p["label"],
            )
            for p in spec["patterns"]
        ]
        hits: list[int] = []
        labels: list[str] = []
        for idx, line in enumerate(lines, start=1):
            for regex, label in compiled:
                if regex.search(line):
                    hits.append(idx)
                    labels.append(label)
                    break
        if not hits:
            continue
        first = hits[0]
        snippet = lines[first - 1].strip()[:SNIPPET_MAX]
        candidates.append(
            Candidate(
                vuln_slug=spec["slug"],
                line_numbers=hits,
                snippet=snippet,
                matched_pattern=labels[0],
                noise_tier=spec["noiseTier"],
            )
        )
    return ScanResult(
        plan_path=plan_path,
        tech_tags=detect_tech(text),
        candidates=candidates,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan an implementation plan for security-relevant language")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--matchers", default=str(Path(__file__).resolve().parents[1] / "matchers.json"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    plan_path = Path(args.plan)
    text = plan_path.read_text(encoding="utf-8")
    matchers = load_matchers(Path(args.matchers))
    result = scan_plan(text, str(plan_path), matchers)
    out = Path(args.out)
    out.write_text(json.dumps(scan_result_to_dict(result), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
