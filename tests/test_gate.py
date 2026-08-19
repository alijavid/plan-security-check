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
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "skill" / "plan-security-check" / "scripts" / "gate.py"
sys.path.insert(0, str(GATE.parent))

from gate import decide_gate, validate_finding  # noqa: E402


def _finding(**overrides):
    base = {
        "severity": "HIGH",
        "vulnSlug": "auth-boundary",
        "title": "Public endpoint has no auth",
        "description": "POST /api/invoices is reachable without a session.",
        "taskId": "1",
        "lineNumbers": [12],
        "recommendation": "Require a session and an org-scoped authorization check.",
        "confidence": "high",
        "revalidation": {
            "verdict": "true-positive",
            "reasoning": "Plan never mentions auth.",
        },
    }
    base.update(overrides)
    return base


def test_high_true_positive_blocks():
    result = decide_gate([_finding()])
    assert result["verdict"] == "BLOCK"
    assert result["blocking"][0]["vulnSlug"] == "auth-boundary"


def test_high_without_revalidation_blocks():
    result = decide_gate([_finding(revalidation=None)])
    assert result["verdict"] == "BLOCK"


def test_high_already_mitigated_passes():
    result = decide_gate(
        [
            _finding(
                revalidation={
                    "verdict": "already-mitigated",
                    "reasoning": "Task 1 step 2 requires session + org check.",
                }
            )
        ]
    )
    assert result["verdict"] == "PASS"


def test_medium_true_positive_warns():
    result = decide_gate([_finding(severity="MEDIUM")])
    assert result["verdict"] == "WARN"


def test_invalid_severity_blocks():
    bad = _finding(severity="INFO")
    result = decide_gate([bad])
    assert result["verdict"] == "BLOCK"
    assert result["reason"] == "invalid-findings"


def _run_gate(findings_path: Path, out: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GATE), "--findings", str(findings_path), "--out", str(out)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_exit_codes(tmp_path: Path):
    findings = tmp_path / "findings.json"
    out = tmp_path / "gate.json"
    findings.write_text(json.dumps({"findings": [_finding()]}), encoding="utf-8")
    proc = _run_gate(findings, out)
    assert proc.returncode == 2
    assert json.loads(out.read_text())["verdict"] == "BLOCK"


def test_cli_pass_exits_0(tmp_path: Path):
    findings = tmp_path / "findings.json"
    out = tmp_path / "gate.json"
    findings.write_text(json.dumps({"findings": []}), encoding="utf-8")
    proc = _run_gate(findings, out)
    assert proc.returncode == 0
    assert json.loads(out.read_text())["verdict"] == "PASS"


def test_cli_warn_exits_1(tmp_path: Path):
    findings = tmp_path / "findings.json"
    out = tmp_path / "gate.json"
    findings.write_text(json.dumps({"findings": [_finding(severity="MEDIUM")]}), encoding="utf-8")
    proc = _run_gate(findings, out)
    assert proc.returncode == 1
    assert json.loads(out.read_text())["verdict"] == "WARN"


def test_cli_missing_file_exits_3(tmp_path: Path):
    out = tmp_path / "gate.json"
    proc = _run_gate(tmp_path / "missing.json", out)
    assert proc.returncode == 3
    assert json.loads(out.read_text())["reason"] == "invalid-findings"
    assert json.loads(out.read_text())["verdict"] == "BLOCK"


def test_cli_invalid_json_exits_3(tmp_path: Path):
    findings = tmp_path / "findings.json"
    out = tmp_path / "gate.json"
    findings.write_text("{not-json", encoding="utf-8")
    proc = _run_gate(findings, out)
    assert proc.returncode == 3
    assert json.loads(out.read_text())["reason"] == "invalid-findings"
    assert json.loads(out.read_text())["verdict"] == "BLOCK"


def test_cli_undecodable_findings_exits_3(tmp_path: Path):
    findings = tmp_path / "findings.json"
    out = tmp_path / "gate.json"
    findings.write_bytes(b"\xff\xfe not utf-8")
    proc = _run_gate(findings, out)
    assert proc.returncode == 3
    assert json.loads(out.read_text())["reason"] == "invalid-findings"
    assert json.loads(out.read_text())["verdict"] == "BLOCK"


def test_cli_write_failure_exits_3(tmp_path: Path):
    findings = tmp_path / "findings.json"
    out = tmp_path / "gate-dir"
    out.mkdir()
    findings.write_text(json.dumps({"findings": []}), encoding="utf-8")
    proc = _run_gate(findings, out)
    assert proc.returncode == 3
