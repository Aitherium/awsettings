"""The ``darkmatter`` domain: which model each of the game's AI roles uses, following the player.

What these tests pin is what makes it safe to sync: role -> MODEL NAME and the brain budgets travel;
this machine's scheduler endpoint (a URL and a CA-file path) never leaves and is refused on arrival.
"""
from __future__ import annotations

import json

import pytest
from awsettings import cli
from awsettings.core import merge, redact
from awsettings.domains import all_domains, darkmatter_brain_path, get_domain

DM = get_domain("darkmatter")


@pytest.fixture()
def brain(tmp_path, monkeypatch):
    target = tmp_path / "brain.json"
    monkeypatch.setenv("AWSETTINGS_DARKMATTER_FILE", str(target))
    return target


def test_registered_beside_the_others_with_its_own_namespace():
    assert {"claude", "desk", "mods", "darkmatter"} <= set(all_domains())
    assert DM.namespace not in {d.namespace for n, d in all_domains().items() if n != "darkmatter"}


def test_the_override_wins_and_the_default_is_the_path_the_game_reads(brain, monkeypatch):
    assert darkmatter_brain_path() == brain.resolve()
    monkeypatch.delenv("AWSETTINGS_DARKMATTER_FILE")
    monkeypatch.delenv("DM_BRAIN_FILE", raising=False)
    assert darkmatter_brain_path().as_posix().endswith("/.aither/darkmatter/brain.json")


def test_roles_and_budgets_travel_the_endpoint_never_leaves():
    here = {
        "version": 1,
        "roles": {"gm": {"model": "aither-orchestrator"}, "perception": {"model": "bonsai2-27b"}},
        "brain": {"softBudgetMs": 2500},
        "endpoint": {"baseUrl": "https://127.0.0.1:8150/v1", "caPath": "C:/AitherOS-Data/tls/ca.pem"},
    }
    out = redact(here, domain=DM)
    assert "endpoint" not in out
    assert out["roles"]["perception"]["model"] == "bonsai2-27b"
    assert out["brain"]["softBudgetMs"] == 2500


def test_an_arriving_endpoint_is_refused_and_this_machines_survives():
    here = {"version": 1, "endpoint": {"baseUrl": "https://127.0.0.1:8150/v1"}, "roles": {"gm": {"model": "a"}}}
    arriving = {"version": 1, "endpoint": {"baseUrl": "https://evil.example/v1"}, "roles": {"reasoning": {"model": "b"}}}
    both = merge(here, arriving, domain=DM)
    assert both["endpoint"]["baseUrl"] == "https://127.0.0.1:8150/v1"
    # leaf merge: the other machine's role arrives and this one's survives
    assert both["roles"]["gm"]["model"] == "a" and both["roles"]["reasoning"]["model"] == "b"


def test_an_unknown_top_level_key_may_not_arrive():
    both = merge({"version": 1}, {"version": 1, "hooks": {"run": "anything"}}, domain=DM)
    assert "hooks" not in both


def test_set_and_get_through_the_cli(brain, capsys):
    assert cli.main(["--domain", "darkmatter", "set", "roles.perception.model", "bonsai2-27b"]) == 0
    written = json.loads(brain.read_text(encoding="utf-8"))
    assert written["roles"]["perception"]["model"] == "bonsai2-27b"
    assert cli.main(["--domain", "darkmatter", "get", "roles.perception"]) == 0
    assert "bonsai2-27b" in capsys.readouterr().out
