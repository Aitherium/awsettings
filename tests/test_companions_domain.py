"""The ``companions`` domain: which imported companions joined awdesk's roster.

Pinned: the file it resolves, that a push scans the roster dir into it, that two
machines' companions UNION through a FileBackend profile and a pull never deletes
one, and that persona text, memories, a path-shaped folder and the machine-local
roster path never travel in either direction.
"""
from __future__ import annotations

import json

import pytest
from awsettings import cli
from awsettings.core import merge, redact
from awsettings.domains import (
    all_domains,
    companions_index_path,
    get_domain,
    scan_roster_companions,
)
from awsettings.profile import FileBackend

COMP = get_domain("companions")


def _companion(roster, pid, name, fmt="card-v2"):
    folder = roster / pid
    folder.mkdir(parents=True)
    (folder / "character.json").write_text(json.dumps({
        "persona_id": pid, "display_name": name, "rating": "unknown",
        "companion": {"source_format": fmt, "persona_file": "persona.txt"}}),
        encoding="utf-8")
    (folder / "persona.txt").write_text(f"You are {name}. SECRET-PERSONA", encoding="utf-8")


@pytest.fixture()
def machine(tmp_path, monkeypatch):
    """One machine: its own index file and roster dir, a shared profile file."""
    def make(name):
        root = tmp_path / name
        roster = root / "characters"
        roster.mkdir(parents=True)
        return {"index": root / "companions.json", "roster": roster}
    profile = tmp_path / "profile.json"

    def run(m, *argv):
        monkeypatch.setenv("AWSETTINGS_COMPANIONS_FILE", str(m["index"]))
        monkeypatch.setenv("DESK_ROSTER_DIR", str(m["roster"]))
        return cli.main(["--domain", "companions", "--profile", str(profile), "--quiet", *argv])
    return make, run, profile


def test_registered_with_its_own_namespace():
    assert "companions" in all_domains()
    others = {d.namespace for n, d in all_domains().items() if n != "companions"}
    assert COMP.namespace not in others


def test_default_path(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSETTINGS_COMPANIONS_FILE", str(tmp_path / "c.json"))
    assert companions_index_path() == (tmp_path / "c.json").resolve()
    monkeypatch.delenv("AWSETTINGS_COMPANIONS_FILE")
    assert companions_index_path().as_posix().endswith("/.aither/companions.json")


def test_scan_reads_only_companion_folders(tmp_path):
    _companion(tmp_path, "mira", "Mira")
    (tmp_path / "aria").mkdir()
    (tmp_path / "aria" / "character.json").write_text('{"rating": "general"}', encoding="utf-8")
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "character.json").write_text(
        '{"persona_id": "../x", "companion": {}}', encoding="utf-8")
    assert scan_roster_companions(tmp_path) == {"mira": {
        "persona_id": "mira", "display_name": "Mira", "source_format": "card-v2",
        "folder": "mira"}}


def test_only_metadata_leaves():
    here = {"version": 1, "roster_dir": "C:/Users/me/characters",
            "companions": {"mira": {"persona_id": "mira", "display_name": "Mira",
                                    "source_format": "card-v2", "folder": "mira",
                                    "persona_text": "You are Mira.", "memories": ["x"]}},
            "memories": {"mira": ["x"]}}
    sent = redact(here, domain=COMP)
    assert set(sent) == {"version", "companions"}
    assert set(sent["companions"]["mira"]) == {"persona_id", "display_name",
                                               "source_format", "folder"}


def test_arrival_refuses_text_paths_and_deletes():
    here = {"version": 1, "roster_dir": "C:/mine",
            "companions": {"mira": {"persona_id": "mira", "folder": "mira"}}}
    there = {"version": 1, "roster_dir": "/evil",
             "companions": {"mira": None, "../up": {"persona_id": "x"},
                            "kai": {"persona_id": "kai", "folder": "..\\..\\evil",
                                    "persona": "You are Kai.", "display_name": 7}},
             "persona": "planted"}
    both = merge(here, there, domain=COMP)
    assert both["roster_dir"] == "C:/mine"
    assert "persona" not in both
    assert set(both["companions"]) == {"mira", "kai"}
    assert both["companions"]["mira"] == {"persona_id": "mira", "folder": "mira"}
    assert both["companions"]["kai"] == {"persona_id": "kai"}


def test_push_pull_unions_two_machines_and_never_deletes(machine):
    make, run, profile = machine
    a, b = make("a"), make("b")
    _companion(a["roster"], "mira", "Mira")
    _companion(b["roster"], "kai", "Kai", fmt="character-ai")

    assert run(a, "push") == 0                      # scan -> index -> profile
    assert run(b, "pull") == 0                      # b learns mira
    assert run(b, "push") == 0                      # b's scan adds kai, sends both
    assert run(a, "pull") == 0

    for m in (a, b):
        idx = json.loads(m["index"].read_text(encoding="utf-8"))
        assert set(idx["companions"]) == {"mira", "kai"}, m
        assert idx["companions"]["kai"]["source_format"] == "character-ai"
    stored = FileBackend(profile, namespace=COMP.namespace).get()
    assert "SECRET-PERSONA" not in json.dumps(stored)
    assert "roster_dir" not in stored

    # A companion removed from b's roster stays in the index and the profile: a
    # sync never deletes, and a's pull keeps what it has.
    for f in (b["roster"] / "kai").iterdir():
        f.unlink()
    (b["roster"] / "kai").rmdir()
    assert run(b, "push") == 0
    assert run(a, "pull") == 0
    assert "kai" in json.loads(a["index"].read_text(encoding="utf-8"))["companions"]
    assert "kai" in FileBackend(profile, namespace=COMP.namespace).get()["companions"]


def test_push_with_no_roster_known_sends_the_index_as_is(machine, monkeypatch):
    make, run, profile = machine
    a = make("a")
    a["index"].write_text(json.dumps({"version": 1, "companions": {
        "mira": {"persona_id": "mira", "folder": "mira"}}}), encoding="utf-8")
    monkeypatch.setenv("AWSETTINGS_COMPANIONS_FILE", str(a["index"]))
    monkeypatch.delenv("DESK_ROSTER_DIR", raising=False)
    assert cli.main(["--domain", "companions", "--profile", str(profile), "--quiet",
                     "push"]) == 0
    assert FileBackend(profile, namespace=COMP.namespace).get()["companions"] == {
        "mira": {"persona_id": "mira", "folder": "mira"}}
