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

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "skill" / "plan-security-check" / "scripts" / "report.py"
sys.path.insert(0, str(REPORT.parent))

from report import render_section, upsert_report  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "plans"


def test_upsert_replaces_existing_section():
    plan = (FIXTURES / "mitigated-public-api.md").read_text(encoding="utf-8")
    section = render_section(
        gate={"verdict": "PASS", "blocking": [], "warnings": []},
        findings=[],
        candidates=[{"vulnSlug": "auth-boundary", "lineNumbers": [12]}],
    )
    updated = upsert_report(plan, section)
    assert updated.count("## Security Check") == 1
    assert "old contents that must be replaced" not in updated
    assert "**Verdict:** PASS" in updated
    assert "auth-boundary" in updated


def test_upsert_appends_when_missing():
    plan = "# Title\n\nbody\n"
    updated = upsert_report(plan, "## Security Check\n\n**Verdict:** WARN\n")
    assert updated.endswith("## Security Check\n\n**Verdict:** WARN\n")


def test_upsert_preserves_backslash_d_in_recommendation():
    plan = "# Title\n\n## Security Check\n\nold contents\n"
    section = render_section(
        gate={"verdict": "BLOCK", "blocking": [{}], "warnings": []},
        findings=[
            {
                "severity": "HIGH",
                "vulnSlug": "injection-sql",
                "title": r"Reject tokens that look like \d",
                "recommendation": r"Bind parameters; do not interpolate \d into SQL.",
                "revalidation": {"verdict": "true-positive"},
            }
        ],
        candidates=[],
    )
    updated = upsert_report(plan, section)
    assert r"\d" in updated
    assert "old contents" not in updated


def test_upsert_preserves_heading_after_security_check():
    plan = (
        "# Title\n\n"
        "## Security Check\n\n"
        "old contents that must be replaced\n\n"
        "## Rollout\n\n"
        "Keep this later section.\n"
    )
    updated = upsert_report(plan, "## Security Check\n\n**Verdict:** PASS\n")
    assert updated.count("## Security Check") == 1
    assert "old contents that must be replaced" not in updated
    assert "## Rollout" in updated
    assert "Keep this later section." in updated


def test_cli_requires_out_without_in_place():
    proc = subprocess.run(
        [
            sys.executable,
            str(REPORT),
            "--plan",
            "p.md",
            "--scan",
            "s.json",
            "--findings",
            "f.json",
            "--gate",
            "g.json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "--out" in proc.stderr
