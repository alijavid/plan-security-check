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

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill" / "plan-security-check"

UPSTREAM_NOTICE = (
    "deepsec\n"
    "Copyright 2026 Vercel, Inc. and contributors\n"
    "\n"
    "This product includes software developed at Vercel, Inc.\n"
    "(https://vercel.com/)."
)

MODIFIED_NOTICE = "This file has been modified from its original form."

DERIVED_PYTHON = [
    SKILL / "scripts" / "scan.py",
    SKILL / "scripts" / "gate.py",
    SKILL / "scripts" / "report.py",
]


def test_root_and_skill_ship_identical_apache_license():
    root = (ROOT / "LICENSE").read_text(encoding="utf-8")
    skill = (SKILL / "LICENSE").read_text(encoding="utf-8")
    assert root == skill
    assert "Apache License" in root
    assert "Version 2.0, January 2004" in root
    assert "http://www.apache.org/licenses/" in root
    assert "4. Redistribution." in root
    assert "APPENDIX: How to apply the Apache License to your work." in root


def test_notice_reproduces_upstream_attribution():
    for path in (ROOT / "NOTICE", SKILL / "NOTICE"):
        text = path.read_text(encoding="utf-8")
        assert text == (ROOT / "NOTICE").read_text(encoding="utf-8")
        assert "Ali Javid" not in text
        assert UPSTREAM_NOTICE in text
        assert "https://github.com/vercel-labs/deepsec" in text
        assert "derivative work" in text
        assert "not affiliated with, sponsored by, or endorsed by" in text


def test_readme_and_pyproject_declare_apache_2():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "Apache License, Version 2.0" in readme
    assert "[LICENSE](LICENSE)" in readme
    assert "[NOTICE](NOTICE)" in readme
    assert 'license = { text = "Apache-2.0" }' in pyproject or 'license = "Apache-2.0"' in pyproject


def test_derived_python_files_carry_apache_header_and_modification_notice():
    for path in DERIVED_PYTHON:
        text = path.read_text(encoding="utf-8")
        assert text.startswith("# Licensed under the Apache License, Version 2.0")
        assert "Ali Javid" not in text
        assert "http://www.apache.org/licenses/LICENSE-2.0" in text
        assert MODIFIED_NOTICE in text


def test_matchers_json_carries_license_and_modification_notice():
    text = (SKILL / "matchers.json").read_text(encoding="utf-8")
    assert '"license": "Apache-2.0"' in text
    assert "Ali Javid" not in text
    assert MODIFIED_NOTICE in text
