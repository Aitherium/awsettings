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


# -- a wiped machine gets its companions back --------------------------------

PASS = "correct horse battery staple 42"
BACKED = {"backup_repo": "me/companions", "last_backup_tag": "companion-mira-20261016T000000Z"}


def _index(m):
    return json.loads(m["index"].read_text(encoding="utf-8"))


def _push_a_with_backup(make, run):
    """Machine A: mira imported AND backed up (the pointer awrtifact records)."""
    a = make("a")
    _companion(a["roster"], "mira", "Mira")
    _companion(a["roster"], "kai", "Kai", fmt="character-ai")
    a["index"].write_text(json.dumps({"version": 1, "companions": {
        "mira": {"persona_id": "mira", **BACKED}}}), encoding="utf-8")
    assert run(a, "push") == 0
    return a


def test_fresh_machine_pull_recreates_roster_and_prints_restore(machine, capsys):
    make, run, profile = machine
    _push_a_with_backup(make, run)
    b = make("b")                                   # wiped: empty roster, no index
    assert run(b, "pull") == 0
    for pid, name in (("mira", "Mira"), ("kai", "Kai")):
        cj = json.loads((b["roster"] / pid / "character.json").read_text(encoding="utf-8"))
        assert cj["persona_id"] == pid and cj["display_name"] == name
        assert isinstance(cj["companion"], dict)      # the desk admits it bodiless
        assert not (b["roster"] / pid / "model.vrm").exists()
        assert not (b["roster"] / pid / "persona.txt").exists()   # text comes with memories
    out = capsys.readouterr().out
    assert "awrtifact companion-restore mira --repo me/companions" in out
    assert "kai: memories NOT backed up" in out
    assert _index(b)["companions"]["mira"]["backup_repo"] == "me/companions"
    stored = FileBackend(profile, namespace=COMP.namespace).get()
    assert stored["companions"]["mira"]["last_backup_tag"] == BACKED["last_backup_tag"]
    assert "SECRET-PERSONA" not in json.dumps(stored)

    # Second pull: already in step, folders present, nothing rewritten.
    before = (b["roster"] / "mira" / "character.json").read_bytes()
    assert run(b, "pull") == 0
    assert (b["roster"] / "mira" / "character.json").read_bytes() == before


def test_pull_dry_run_writes_no_folder(machine, capsys):
    make, run, _ = machine
    _push_a_with_backup(make, run)
    b = make("b")
    assert run(b, "pull", "--dry-run") == 0
    assert not (b["roster"] / "mira").exists()
    assert not b["index"].exists()
    assert "would recreate mira" in capsys.readouterr().out


def test_restore_memories_runs_the_restore_with_the_env_passphrase(machine, monkeypatch, capsys):
    import sys
    import types
    make, run, profile = machine
    _push_a_with_backup(make, run)
    calls = []
    fake = types.ModuleType("awrtifact.companion")

    def _restore(pid, repo, passphrase, **kw):
        calls.append((pid, repo, passphrase))
        return {"rows_added": 3}
    fake.restore = _restore
    pkg = types.ModuleType("awrtifact")
    pkg.companion = fake
    monkeypatch.setitem(sys.modules, "awrtifact", pkg)
    monkeypatch.setitem(sys.modules, "awrtifact.companion", fake)

    b = make("b")
    monkeypatch.delenv("AWRTIFACT_COMPANION_PASSPHRASE", raising=False)
    # no passphrase: says how
    assert run(b, "pull", "--restore-memories", "--trust-repo", "me/companions") == 0
    assert calls == []
    assert "set $AWRTIFACT_COMPANION_PASSPHRASE" in capsys.readouterr().out

    monkeypatch.setenv("AWRTIFACT_COMPANION_PASSPHRASE", PASS)
    monkeypatch.delenv("AWSETTINGS_TRUSTED_BACKUP_REPOS", raising=False)
    # A repo named only by the synced index is never fetched automatically.
    assert run(b, "pull", "--restore-memories") == 0
    assert calls == []
    assert "--trust-repo me/companions" in capsys.readouterr().out
    assert run(b, "pull", "--restore-memories", "--trust-repo", "me/companions") == 0
    assert calls == [("mira", "me/companions", PASS)]        # kai has no backup
    out = capsys.readouterr()
    assert "mira: memories restored from me/companions" in out.out
    for text in (out.out, out.err, b["index"].read_text(encoding="utf-8"),
                 profile.read_text(encoding="utf-8")):
        assert PASS not in text

    def _boom(*a, **kw):
        raise ValueError("wrong passphrase")
    fake.restore = _boom
    assert run(b, "pull", "--restore-memories", "--trust-repo", "me/companions") == 2
    assert "memory restore FAILED" in capsys.readouterr().out


def test_pull_refuses_a_folder_owned_by_another_persona(machine, capsys):
    make, run, _ = machine
    _push_a_with_backup(make, run)
    b = make("b")
    (b["roster"] / "mira").mkdir()
    squatter = json.dumps({"persona_id": "someone-else", "companion": {}})
    (b["roster"] / "mira" / "character.json").write_text(squatter, encoding="utf-8")
    (b["roster"] / "kai").mkdir()
    (b["roster"] / "kai" / "model.vrm").write_bytes(b"x")   # files, no character.json
    assert run(b, "pull") == 1
    assert (b["roster"] / "mira" / "character.json").read_text(encoding="utf-8") == squatter
    assert not (b["roster"] / "kai" / "character.json").exists()
    out = capsys.readouterr().out
    assert "REFUSED mira" in out and "REFUSED kai" in out


def test_inbound_backup_pointer_must_be_well_shaped():
    there = {"version": 1, "companions": {
        "mira": {"persona_id": "mira", "backup_repo": "me/x; rm -rf ~",
                 "last_backup_tag": "v1", "passphrase": "hunter2"}}}
    both = merge({}, there, domain=COMP)
    assert both["companions"]["mira"] == {"persona_id": "mira"}


def test_push_dry_run_scans_the_roster_and_writes_nothing(machine, monkeypatch, capsys):
    make, _run, profile = machine
    a = make("a")
    _companion(a["roster"], "mira", "Mira")
    monkeypatch.setenv("AWSETTINGS_COMPANIONS_FILE", str(a["index"]))
    monkeypatch.setenv("DESK_ROSTER_DIR", str(a["roster"]))
    assert cli.main(["--domain", "companions", "--profile", str(profile),
                     "push", "--dry-run"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["companions"]["mira"]["folder"] == "mira"
    assert "roster scan would update" in out.err
    assert "SECRET-PERSONA" not in out.out
    assert not a["index"].exists() and not profile.exists()
