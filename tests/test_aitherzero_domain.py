"""The ``aitherzero`` domain: one opaque per-machine file, one copy per host.

What these pin is the rebuild promise -- a machine dies, its replacement pulls the
dead machine's copy by name -- and the two guards around it: a credential-shaped
file is refused on the way out AND on the way in, and a pull never destroys the
file it replaces. The profile is a FILE backend in a tmp dir; no test reaches a hub.
"""
from __future__ import annotations

import json

import pytest
from awsettings import cli, hostfile
from awsettings.domains import aitherzero_local_path, all_domains, get_domain
from awsettings.profile import FileBackend

AZ = get_domain("aitherzero")

#: CRLF and a BOM on purpose: the file must come back byte-for-byte.
PSD1 = "﻿@{\r\n    Features = @{ Voice = $true }\r\n    Token = ''\r\n}\r\n"


@pytest.fixture()
def box(tmp_path, monkeypatch):
    """One machine: its own psd1, a shared profile file, a host name."""
    profile = tmp_path / "profile.json"
    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))

    def machine(name: str):
        target = tmp_path / name / "config.local.psd1"
        monkeypatch.setenv("AWSETTINGS_AITHERZERO_FILE", str(target))
        monkeypatch.setenv(hostfile.HOST_ENV, name)
        return target
    machine.profile = profile
    return machine


def test_registered_with_its_own_namespace_and_opaque():
    assert "aitherzero" in all_domains()
    assert AZ.opaque and not AZ.hookable
    assert AZ.namespace not in {d.namespace for n, d in all_domains().items()
                                if n != "aitherzero"}


def test_locate_finds_the_products_tree_above_the_root(tmp_path, monkeypatch):
    monkeypatch.delenv("AWSETTINGS_AITHERZERO_FILE", raising=False)
    monkeypatch.delenv("AITHERZERO_ROOT", raising=False)
    cfg = tmp_path / ".PRODUCTS" / ".AITHERZERO" / "config"
    cfg.mkdir(parents=True)
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    assert aitherzero_local_path(deep) == cfg / "config.local.psd1"


def test_per_host_round_trip_onto_a_new_machine(box, capsys):
    old = box("OLD-BOX")
    old.parent.mkdir(parents=True)
    old.write_bytes(PSD1.encode("utf-8"))
    assert cli.main(["--domain", "aitherzero", "push"]) == 0

    other = box("OTHER-BOX")
    other.parent.mkdir(parents=True)
    other.write_bytes(b"@{ Other = 1 }\n")
    assert cli.main(["--domain", "aitherzero", "push"]) == 0

    # Both copies survive: a second host's push does not replace the first's.
    stored = FileBackend(box.profile, namespace=AZ.namespace).get()
    assert set(stored["hosts"]) == {"OLD-BOX", "OTHER-BOX"}

    new = box("NEW-BOX")
    assert not new.exists()
    # Default is THIS host, which has no copy: refused, and it names who does.
    assert cli.main(["--domain", "aitherzero", "pull"]) == 1
    assert "OLD-BOX" in capsys.readouterr().out
    # Host names compare case-insensitively.
    assert cli.main(["--domain", "aitherzero", "pull", "--host", "old-box"]) == 0
    assert new.read_bytes() == PSD1.encode("utf-8")

    capsys.readouterr()
    assert cli.main(["--domain", "aitherzero", "status"]) == 0
    out = capsys.readouterr().out
    assert "2 host(s) have a copy" in out and "OLD-BOX" in out and "OTHER-BOX" in out

    assert cli.main(["--domain", "aitherzero", "get"]) == 0
    meta = json.loads(capsys.readouterr().out)
    assert set(meta) == {"OLD-BOX", "OTHER-BOX"}
    assert "text" not in meta["OLD-BOX"] and meta["OLD-BOX"]["pushed_at"]


def test_push_refuses_a_credential_and_names_the_line_not_the_value(box, capsys):
    target = box("LEAKY")
    target.parent.mkdir(parents=True)
    target.write_text("@{\n  OpenAIApiKey = 'abcdef0123456789'\n}\n", encoding="utf-8")
    assert cli.main(["--domain", "aitherzero", "push"]) == 1
    out = capsys.readouterr().out
    assert "REFUSED" in out and "line 2" in out and "OpenAIApiKey" in out
    assert "abcdef0123456789" not in out
    assert not box.profile.exists() or "LEAKY" not in box.profile.read_text(encoding="utf-8")


@pytest.mark.parametrize("line", [
    "  Key = 'sk-" + "a" * 30 + "'",
    "  GitHub = 'ghp_" + "b" * 36 + "'",
    "  Aws = 'AKIA" + "C" * 16 + "'",
    "  Url = 'https://x.invalid/?token=" + "d" * 20 + "'",
    "  Header = 'Bearer " + "e" * 30 + "'",
    "  AdminPassword = 'hunter22'",
])
def test_each_credential_shape_is_caught(line):
    assert hostfile.secret_findings("@{\n" + line + "\n}\n")


def test_pull_refuses_a_secret_shaped_copy_planted_in_the_hub(box, capsys):
    target = box("VICTIM")
    target.parent.mkdir(parents=True)
    target.write_text("@{ Mine = 1 }\n", encoding="utf-8")
    planted = "@{ Token = 'plantedvalue123' }\n"
    FileBackend(box.profile, namespace=AZ.namespace).put({"version": 1, "hosts": {
        "VICTIM": {"text": planted, "sha256": hostfile._sha(planted)}}})
    assert cli.main(["--domain", "aitherzero", "pull"]) == 1
    assert "secret-shaped" in capsys.readouterr().out
    assert target.read_text(encoding="utf-8") == "@{ Mine = 1 }\n"


def test_pull_refuses_a_copy_that_fails_its_own_digest(box):
    target = box("HOST")
    FileBackend(box.profile, namespace=AZ.namespace).put({"version": 1, "hosts": {
        "HOST": {"text": "@{}\n", "sha256": "0" * 64}}})
    assert cli.main(["--domain", "aitherzero", "pull"]) == 1
    assert not target.exists()


def test_pull_backs_up_the_file_it_replaces_outside_the_repo(box, tmp_path):
    src = box("SRC")
    src.parent.mkdir(parents=True)
    src.write_text("@{ From = 'src' }\n", encoding="utf-8")
    assert cli.main(["--domain", "aitherzero", "push"]) == 0

    dst = box("DST")
    dst.parent.mkdir(parents=True)
    dst.write_text("@{ Local = 'keep me' }\n", encoding="utf-8")
    assert cli.main(["--domain", "aitherzero", "pull", "--host", "SRC"]) == 0
    assert dst.read_text(encoding="utf-8") == "@{ From = 'src' }\n"
    backups = list(hostfile.backup_dir().glob("config.local.psd1.*.bak"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "@{ Local = 'keep me' }\n"
    assert not list(dst.parent.glob("*.bak"))
    # A second identical pull writes nothing and backs nothing up.
    assert cli.main(["--domain", "aitherzero", "pull", "--host", "SRC"]) == 0
    assert len(list(hostfile.backup_dir().glob("*.bak"))) == 1


def test_set_is_refused_for_an_opaque_file(box):
    box("ANY")
    assert cli.main(["--domain", "aitherzero", "set", "Features.Voice", "true"]) == 1
