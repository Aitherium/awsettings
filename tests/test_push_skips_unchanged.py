"""A hook push (--debounce) of settings identical to the last push sends nothing.

2026-10-19: the PostToolUse hook re-sent the same 65 KB project settings every few
seconds from dozens of sessions; each PUT rewrote the owner's directory entry.
"""

from __future__ import annotations

import json
import os
import time
import types

from awsettings import cli


class _CountingServer:
    def __init__(self):
        self.puts = 0

    def put(self, snapshot):
        self.puts += 1

    def describe(self):
        return "fake"


def _args(root, debounce=True):
    return types.SimpleNamespace(
        url=None, profile=None, root=str(root), user=False, domain="claude",
        quiet=True, dry_run=False, debounce=debounce, sign=False, prune_denies=False,
    )


def _setup(tmp_path, monkeypatch):
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}}), encoding="utf-8")
    server = _CountingServer()
    monkeypatch.setattr(cli, "resolve", lambda *a, **k: server)
    monkeypatch.setattr(cli, "DEBOUNCE_SECONDS", 0)
    return settings, server


def test_unchanged_settings_are_pushed_once(tmp_path, monkeypatch):
    _, server = _setup(tmp_path, monkeypatch)
    for _ in range(5):
        assert cli.cmd_push(_args(tmp_path)) == 0
    assert server.puts == 1


def test_a_changed_setting_is_pushed(tmp_path, monkeypatch):
    settings, server = _setup(tmp_path, monkeypatch)
    cli.cmd_push(_args(tmp_path))
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(pwd)"]}}), encoding="utf-8")
    cli.cmd_push(_args(tmp_path))
    assert server.puts == 2


def test_an_explicit_push_always_sends(tmp_path, monkeypatch):
    _, server = _setup(tmp_path, monkeypatch)
    cli.cmd_push(_args(tmp_path, debounce=False))
    cli.cmd_push(_args(tmp_path, debounce=False))
    assert server.puts == 2


def test_unchanged_settings_are_resent_after_an_hour(tmp_path, monkeypatch):
    _, server = _setup(tmp_path, monkeypatch)
    cli.cmd_push(_args(tmp_path))
    dom = cli._dom(_args(tmp_path))
    marker = cli._content_stamp(cli._stamp(dom, _args(tmp_path)), dom.locate(str(tmp_path)))
    old = time.time() - cli.UNCHANGED_RESEND_SECONDS - 5
    os.utime(marker, (old, old))
    cli.cmd_push(_args(tmp_path))
    assert server.puts == 2


def test_two_worktrees_with_different_files_each_push_once(tmp_path, monkeypatch):
    server = _CountingServer()
    monkeypatch.setattr(cli, "resolve", lambda *a, **k: server)
    monkeypatch.setattr(cli, "DEBOUNCE_SECONDS", 0)
    roots = []
    for name, rule in (("a", "Bash(ls)"), ("b", "Bash(pwd)")):
        root = tmp_path / name
        (root / ".claude").mkdir(parents=True)
        (root / ".claude" / "settings.local.json").write_text(
            json.dumps({"permissions": {"allow": [rule]}}), encoding="utf-8")
        roots.append(root)
    for _ in range(3):
        for root in roots:
            cli.cmd_push(_args(root))
    assert server.puts == 2
