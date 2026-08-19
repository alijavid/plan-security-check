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
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill" / "plan-security-check"
sys.path.insert(0, str(SKILL / "scripts"))

from scan import Candidate, ScanResult, candidate_to_dict, scan_result_to_dict  # noqa: E402
from scan import detect_tech, load_matchers, scan_plan  # noqa: E402


FIXTURES = Path(__file__).parent / "fixtures" / "plans"


def test_candidate_to_dict_shape():
    c = Candidate(
        vuln_slug="auth-boundary",
        line_numbers=[12],
        snippet="Add a POST /api/invoices endpoint",
        matched_pattern="ingress surface",
        noise_tier="noisy",
    )
    d = candidate_to_dict(c)
    assert d == {
        "vulnSlug": "auth-boundary",
        "lineNumbers": [12],
        "snippet": "Add a POST /api/invoices endpoint",
        "matchedPattern": "ingress surface",
        "noiseTier": "noisy",
    }
    json.dumps(d)  # must be JSON-serializable


def test_scan_result_to_dict_shape():
    result = ScanResult(
        plan_path="/tmp/plan.md",
        tech_tags=["nextjs"],
        candidates=[],
    )
    d = scan_result_to_dict(result)
    assert d["planPath"] == "/tmp/plan.md"
    assert d["techTags"] == ["nextjs"]
    assert d["candidates"] == []


def test_detect_tech_from_stack_line():
    text = "**Tech Stack:** Next.js, Postgres, GitHub Actions\n"
    assert detect_tech(text) == ["nextjs", "github-actions"]
    assert "go" not in detect_tech("**Architecture:** One markdown edit.\n")


def test_scan_flags_public_endpoint_and_webhook():
    matchers = load_matchers(SKILL / "matchers.json")
    text = (FIXTURES / "vulnerable-public-api.md").read_text(encoding="utf-8")
    result = scan_plan(text, "vulnerable-public-api.md", matchers)
    slugs = {c.vuln_slug for c in result.candidates}
    assert "auth-boundary" in slugs
    assert "webhook-unverified" in slugs
    assert all(c.line_numbers for c in result.candidates)


def test_scan_docs_only_has_no_precise_hits():
    matchers = load_matchers(SKILL / "matchers.json")
    text = (FIXTURES / "docs-only.md").read_text(encoding="utf-8")
    result = scan_plan(text, "docs-only.md", matchers)
    precise = [c for c in result.candidates if c.noise_tier == "precise"]
    assert precise == []


def test_load_matchers_requires_list(tmp_path: Path):
    path = tmp_path / "matchers.json"
    path.write_text(json.dumps({"matchers": {"slug": "nope"}}), encoding="utf-8")
    try:
        load_matchers(path)
    except ValueError as exc:
        assert "matchers" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError when matchers is not a list")
