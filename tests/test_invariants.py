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

from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / "skill" / "plan-security-check"


def test_process_prompt_requires_json_schema_and_always_process():
    text = (SKILL / "process-prompt.md").read_text(encoding="utf-8")
    assert "```json" in text
    assert "always-process" in text.lower()
    assert "revalidation" in text.lower()


def test_revalidate_prompt_lists_four_verdicts():
    text = (SKILL / "revalidate-prompt.md").read_text(encoding="utf-8")
    for verdict in ("true-positive", "false-positive", "already-mitigated", "uncertain"):
        assert verdict in text


def test_threat_classes_cover_required_slugs():
    text = (SKILL / "threat-classes.md").read_text(encoding="utf-8")
    for slug in (
        "auth-boundary",
        "injection-sql",
        "ssrf",
        "secrets",
        "agent-tool-egress",
        "ci-untrusted-checkout",
    ):
        assert slug in text


def test_skill_frontmatter_and_triggers():
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert text.startswith("---\n")
    assert "name: plan-security-check" in text
    assert "disable-model-invocation" not in text
    desc = text.split("description:", 1)[1].split("\n---", 1)[0]
    assert "writing-plans" in desc.lower() or "implementation plan" in desc.lower()
    assert "before" in desc.lower()
    assert len(desc) <= 1024


def test_skill_runbook_has_gate_commands_and_block_rule():
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert "scripts/scan.py" in text
    assert "scripts/gate.py" in text
    assert "scripts/report.py" in text
    assert "Do not offer plan execution" in text
    assert "process-prompt.md" in text
    assert "revalidate-prompt.md" in text
    assert "delete" in text.lower()
    assert ".scan.json" in text
    assert ".findings.json" in text
    assert ".gate.json" in text


def test_skill_under_500_lines():
    lines = (SKILL / "SKILL.md").read_text(encoding="utf-8").splitlines()
    assert len(lines) < 500
