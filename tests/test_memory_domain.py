"""The ``memory`` domain: what a new machine needs to pull this owner's memory back.

Pinned: the file it resolves, that per-project records merge per project and per
field, that a machine-local PATH never travels in either direction, and that a
credential-named key cannot arrive through a profile.
"""
from __future__ import annotations

import json

import pytest
from awsettings import cli
from awsettings.core import merge, redact
from awsettings.domains import all_domains, get_domain, memory_config_path

MEM = get_domain("memory")


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    target = tmp_path / "config.json"
    monkeypatch.setenv("AWSETTINGS_MEMORY_FILE", str(target))
    return target


def test_registered_beside_the_others_with_its_own_namespace():
    assert {"claude", "desk", "mods", "memory"} <= set(all_domains())
    others = {d.namespace for n, d in all_domains().items() if n != "memory"}
    assert MEM.namespace not in others


def test_default_path_is_the_landers_config(cfg, monkeypatch):
    assert memory_config_path() == cfg.resolve()
    monkeypatch.delenv("AWSETTINGS_MEMORY_FILE")
    assert memory_config_path().as_posix().endswith("/.aither/memory-lander/config.json")


def test_only_the_non_secret_keys_leave():
    here = {"version": 1, "targets": ["awm", "share", "strata"], "budget": 22000,
            "strata_prefix": "aither://warm/knowledge/claude-memory/",
            "projects": {"C--P": {"digest": "d" * 64, "public_key": "ab" * 32}},
            "bundles_root": "C:/Users/me/.aither/memory-lander/bundles",
            "signing_key": "C:/Users/me/.aither/awseal/signing.key"}
    sent = redact(here, domain=MEM)
    assert set(sent) == {"version", "targets", "budget", "strata_prefix", "projects"}


def test_projects_merge_per_project_and_per_field():
    here = {"version": 1, "projects": {"A": {"digest": "a1", "public_key": "k"},
                                       "B": {"digest": "b1", "public_key": "k"}}}
    there = {"version": 1, "projects": {"B": {"digest": "b2"}, "C": {"digest": "c1"}}}
    both = merge(here, there, domain=MEM)
    assert set(both["projects"]) == {"A", "B", "C"}
    assert both["projects"]["B"] == {"digest": "b2", "public_key": "k"}


def test_a_path_or_credential_may_not_arrive():
    both = merge({"version": 1},
                 {"version": 1, "bundles_root": "/evil", "private_key": "x",
                  "hooks": {"run": "anything"}}, domain=MEM)
    assert set(both) == {"version"}


def test_set_writes_version_and_value(cfg):
    assert cli.main(["--domain", "memory", "set", "budget", "22000"]) == 0
    assert json.loads(cfg.read_text(encoding="utf-8")) == {"budget": 22000, "version": 1}
