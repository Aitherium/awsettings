"""The ``mods`` domain: a coding agent's default route for its `aw` subagent.

The file is read by a Claude Code hooks module on every spawn, so what these tests
pin is what that reader depends on: the shape `set` writes, that one machine's
daemon address never travels in either direction, and that a pull cannot smuggle
in a key the mod would not have written.
"""
from __future__ import annotations

import json

import pytest
from awsettings import cli
from awsettings.core import merge, redact
from awsettings.domains import all_domains, get_domain, mods_path

MODS = get_domain("mods")


@pytest.fixture()
def mods(tmp_path, monkeypatch):
    target = tmp_path / "mods.json"
    monkeypatch.setenv("AWSETTINGS_MODS_FILE", str(target))
    return target


def test_the_domain_is_registered_beside_the_others_not_instead_of_them():
    assert {"claude", "desk", "mods"} <= set(all_domains())
    assert MODS.namespace not in {d.namespace for n, d in all_domains().items() if n != "mods"}


def test_the_override_wins_and_the_default_is_the_path_the_mod_reads(mods, monkeypatch):
    assert mods_path() == mods.resolve()
    monkeypatch.delenv("AWSETTINGS_MODS_FILE")
    assert mods_path().as_posix().endswith("/.aither/mods.json")


def test_set_writes_the_shape_the_mod_parses(mods, capsys):
    assert cli.main(["--domain", "mods", "set", "aw.harness", "opencode"]) == 0
    assert cli.main(["--domain", "mods", "set", "aw.backend", "kimi-k3"]) == 0
    written = json.loads(mods.read_text(encoding="utf-8"))
    assert written == {"aw": {"harness": "opencode", "backend": "kimi-k3"}, "version": 1}
    assert cli.main(["--domain", "mods", "get", "aw.harness"]) == 0
    assert "opencode" in capsys.readouterr().out


def test_the_daemon_address_stays_home_in_both_directions():
    here = {"version": 1, "aw": {"harness": "codex", "daemon": "http://127.0.0.1:8362"}}
    assert "daemon" not in redact(here, domain=MODS)["aw"]
    arriving = {"version": 1, "aw": {"model": "glm", "daemon": "http://10.0.0.9:1"}}
    both = merge(here, arriving, domain=MODS)
    assert both["aw"]["daemon"] == "http://127.0.0.1:8362"
    # Leaf merge: the other machine's model arrives and this one's harness survives.
    assert both["aw"]["harness"] == "codex" and both["aw"]["model"] == "glm"


def test_an_unknown_top_level_key_may_not_arrive():
    both = merge({"version": 1}, {"version": 1, "hooks": {"run": "anything"}}, domain=MODS)
    assert "hooks" not in both


def test_a_malformed_mods_file_is_never_overwritten_by_set(mods):
    mods.write_text("{ not json", encoding="utf-8")
    assert cli.main(["--domain", "mods", "set", "aw.harness", "aider"]) != 0
    assert mods.read_text(encoding="utf-8") == "{ not json"
