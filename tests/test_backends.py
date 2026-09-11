"""The backend roster: what this machine can launch a coding session on.

Every case here is a defect that actually shipped or nearly did. The roster is
consumed by pickers in other surfaces, and each failure mode below presents as
"the backend list is wrong" with nothing raising.
"""

from __future__ import annotations

import json

import pytest
from awsettings.backends import (
    _SHIM_SCRIPT,
    _SHIM_USE,
    Backend,
    CouldNotJudgeError,
    discover,
    self_test,
)

QUOTED_SHIM = (
    "@echo off\r\n"
    "pwsh -NoProfile -ExecutionPolicy Bypass -File "
    '"C:\\repo\\tools\\claude-backend\\claude-backend.ps1" use deepseek %*\r\n'
)
FORWARDING_SHIM = (
    '@echo off\r\npwsh -File "C:\\repo\\tools\\claude-backend\\claude-backend.ps1" %*\r\n'
)

PROFILES = {
    "_README": ["prose, not a profile"],
    "anthropic": {"vars": None},
    "deepseek": {
        "vars": {
            "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
            "ANTHROPIC_MODEL": "deepseek-v4-flash[1m]",
        }
    },
    "kimi-k3": {
        "vars": {
            "ANTHROPIC_BASE_URL": "https://api.moonshot.ai/anthropic",
            "ANTHROPIC_MODEL": "kimi-k3",
        }
    },
}


def _write_shim(bin_dir, name: str, body: str):
    path = bin_dir / name
    path.write_text(body, encoding="utf-8")
    return path


def test_shim_parser_reads_a_quoted_script_path():
    """The original bug: every shim quotes the path, the pattern demanded space.

    A regex requiring whitespace straight after `.ps1` matched nothing, so the
    roster silently collapsed to the default backend -- a backend picker with no
    backends to pick, and no error anywhere.
    """
    assert _SHIM_USE.search(QUOTED_SHIM).group(1) == "deepseek"
    assert _SHIM_SCRIPT.search(QUOTED_SHIM).group(1).endswith("claude-backend.ps1")


def test_forwarding_shim_is_not_a_backend():
    """`cbs` forwards its own subcommand; it names no profile and offers nothing."""
    assert _SHIM_USE.search(FORWARDING_SHIM) is None


def test_default_is_always_first_and_always_present():
    found = discover(bin_dir="/nope", profiles={}, have_command=lambda n: True)
    assert [b.id for b in found] == ["default"]
    assert found[0].launcher == "claude"
    assert found[0].model == ""


def test_absent_harness_is_reported_not_hidden():
    found = discover(bin_dir="/nope", profiles={}, have_command=lambda n: False)
    assert found[0].launchable is False
    assert "not on PATH" in found[0].hint


def test_documentation_keys_are_never_offered():
    found = discover(bin_dir="/nope", profiles=PROFILES, have_command=lambda n: True)
    assert "_README" not in [b.id for b in found]


def test_profile_without_a_shim_is_shown_as_unlaunchable():
    """Hiding it would make configured-but-unreachable look like not-configured."""
    found = discover(bin_dir="/nope", profiles=PROFILES, have_command=lambda n: True)
    deepseek = next(b for b in found if b.id == "deepseek")
    assert deepseek.launchable is False
    assert "no launcher shim" in deepseek.hint


def test_a_shim_makes_its_profile_launchable(tmp_path):
    _write_shim(tmp_path, "cds.cmd", QUOTED_SHIM)
    found = discover(bin_dir=tmp_path, profiles=PROFILES, have_command=lambda n: True)
    deepseek = next(b for b in found if b.id == "deepseek")
    assert deepseek.launchable is True
    assert deepseek.launcher == "cds"
    assert deepseek.model == "deepseek-v4-flash[1m]"
    assert deepseek.base_url == "https://api.deepseek.com/anthropic"


def test_a_shim_naming_a_missing_profile_is_not_offered(tmp_path):
    """It dies at launch, after the terminal is already open. Do not offer it."""
    _write_shim(tmp_path, "cxs.cmd", QUOTED_SHIM.replace("use deepseek", "use ghost"))
    found = discover(bin_dir=tmp_path, profiles=PROFILES, have_command=lambda n: True)
    assert "ghost" not in [b.id for b in found]


def test_a_shim_whose_launcher_is_off_path_is_marked_not_dropped(tmp_path):
    _write_shim(tmp_path, "cds.cmd", QUOTED_SHIM)
    found = discover(
        bin_dir=tmp_path,
        profiles=PROFILES,
        have_command=lambda n: n != "cds",
    )
    deepseek = next(b for b in found if b.id == "deepseek")
    assert deepseek.launchable is False
    assert "cds" in deepseek.hint


def test_two_spellings_of_one_backend_collapse(tmp_path):
    """`cas` is the explicit default; two identical rows read as two choices."""
    _write_shim(tmp_path, "cas.cmd", QUOTED_SHIM.replace("use deepseek", "use twin"))
    _write_shim(tmp_path, "cds.cmd", QUOTED_SHIM)
    profiles = dict(PROFILES)
    profiles["twin"] = {
        "vars": {
            "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
            "ANTHROPIC_MODEL": "deepseek-v4-flash[1m]",
        }
    }
    found = discover(bin_dir=tmp_path, profiles=profiles, have_command=lambda n: True)
    models = [(b.model, b.base_url) for b in found]
    assert len(models) == len(set(models))


def test_an_unreadable_profile_file_is_dead_not_empty(tmp_path, monkeypatch):
    """Exit-2 semantics: a probe that cannot judge must not read as one backend."""
    broken = tmp_path / "profiles.json"
    broken.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("AWSETTINGS_BACKEND_PROFILES", str(broken))
    with pytest.raises(CouldNotJudgeError):
        discover(bin_dir="/nope", have_command=lambda n: True)


def test_roster_is_json_serialisable():
    """Other surfaces consume this over a pipe; a dataclass that will not encode
    is a picker that renders nothing."""
    found = discover(bin_dir="/nope", profiles=PROFILES, have_command=lambda n: True)
    payload = json.dumps([b.as_dict() for b in found])
    restored = json.loads(payload)
    assert all({"id", "launcher", "model", "launchable"} <= set(r) for r in restored)
    assert isinstance(Backend(id="x", launcher="y", model="z").as_dict(), dict)


def test_self_test_passes():
    assert self_test() == 0
