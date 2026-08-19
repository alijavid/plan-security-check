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

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill" / "plan-security-check"
sys.path.insert(0, str(SKILL / "scripts"))

from scan import load_matchers, validate_matcher  # noqa: E402

REQUIRED_SLUGS = {
    "auth-boundary",
    "injection-sql",
    "ssrf",
    "path-traversal",
    "xss",
    "secrets",
    "command-injection",
    "insecure-deser",
    "cors-wildcard",
    "webhook-unverified",
    "mass-assignment",
    "crypto-weak",
    "agent-tool-egress",
    "ci-untrusted-checkout",
}

FORBIDDEN_REGEX = re.compile(r"\(\?\<|[\\][1-9]|\(\.\+\)\+|\(\.\*\)\+")


def test_catalog_has_required_slugs():
    matchers = load_matchers(SKILL / "matchers.json")
    slugs = {m["slug"] for m in matchers}
    assert REQUIRED_SLUGS <= slugs


def test_each_matcher_valid_and_examples_match():
    matchers = load_matchers(SKILL / "matchers.json")
    for spec in matchers:
        validate_matcher(spec)
        compiled = [
            re.compile(p["regex"], _flags(p.get("flags", "i")))
            for p in spec["patterns"]
        ]
        for example in spec["examples"]:
            assert any(c.search(example) for c in compiled), (
                f"{spec['slug']} example did not match: {example!r}"
            )


def test_injection_sql_ignores_non_sql_concatenation_and_plain_text():
    matchers = load_matchers(SKILL / "matchers.json")
    spec = next(m for m in matchers if m["slug"] == "injection-sql")
    compiled = [
        re.compile(p["regex"], _flags(p.get("flags", "i"))) for p in spec["patterns"]
    ]
    negatives = (
        "Use string concatenation for the display name",
        "Store the bio as plain text (UTF-8)",
    )
    for sample in negatives:
        assert not any(c.search(sample) for c in compiled), sample


def test_regex_safety_contract():
    matchers = load_matchers(SKILL / "matchers.json")
    for spec in matchers:
        for pattern in spec["patterns"]:
            assert pattern.get("flags", "i") in {"i", "m", "im"}
            assert not FORBIDDEN_REGEX.search(pattern["regex"]), pattern["regex"]
            assert "(?" not in pattern["regex"] or pattern["regex"].startswith(
                "(?i"
            ) is False
            assert r"\1" not in pattern["regex"]


def _flags(raw: str) -> int:
    value = 0
    if "i" in raw:
        value |= re.IGNORECASE
    if "m" in raw:
        value |= re.MULTILINE
    return value
