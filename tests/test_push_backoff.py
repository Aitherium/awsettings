"""A hook push (--debounce) that cannot reach the store backs off instead of paying
the dead round trip again on every tool call.

2026-10-26: the store answered 503 for hours. A failed push wrote no debounce stamp,
so the PostToolUse hook in every session retried it after every tool call
(~1.2-1.8 s each).
"""

from __future__ import annotations

import json
import os
import time
import types

from awsettings import cli
from awsettings.store import CouldNotRunError


class _Store:
    def __init__(self):
        self.up = False
        self.attempts = 0

    def put(self, snapshot):
        self.attempts += 1
        if not self.up:
            raise CouldNotRunError("GET https://store.invalid/preferences: 503")

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
    store = _Store()
    monkeypatch.setattr(cli, "resolve", lambda *a, **k: store)
    monkeypatch.setattr(cli, "DEBOUNCE_SECONDS", 0)
    return store


def _failed_marker(root):
    args = _args(root)
    return cli._failed_stamp(cli._stamp(cli._dom(args), args))


def test_a_dead_store_is_tried_once_per_backoff_window(tmp_path, monkeypatch):
    store = _setup(tmp_path, monkeypatch)
    assert cli.cmd_push(_args(tmp_path)) == 2       # the first failure is reported
    for _ in range(5):
        assert cli.cmd_push(_args(tmp_path)) == 0   # then the hooks stop paying for it
    assert store.attempts == 1


def test_the_store_is_retried_once_the_backoff_expires(tmp_path, monkeypatch):
    store = _setup(tmp_path, monkeypatch)
    cli.cmd_push(_args(tmp_path))
    old = time.time() - cli.FAILED_PUSH_BACKOFF_SECONDS - 5
    os.utime(_failed_marker(tmp_path), (old, old))
    store.up = True
    assert cli.cmd_push(_args(tmp_path)) == 0
    assert store.attempts == 2
    assert not _failed_marker(tmp_path).exists()    # a success clears the backoff


def test_an_explicit_push_ignores_the_backoff(tmp_path, monkeypatch):
    store = _setup(tmp_path, monkeypatch)
    cli.cmd_push(_args(tmp_path))
    assert cli.cmd_push(_args(tmp_path, debounce=False)) == 2
    assert store.attempts == 2


def test_an_unchanged_push_never_resolves_the_token(tmp_path, monkeypatch):
    """2026-10-26: resolve() spent ~0.8-1.3 s in a token subprocess BEFORE the
    unchanged-settings skip, so every tool call in every session paid it."""
    store = _setup(tmp_path, monkeypatch)
    store.up = True
    calls = []

    def counting_resolve(*a, **k):
        calls.append(a)
        return store

    monkeypatch.setattr(cli, "resolve", counting_resolve)
    assert cli.cmd_push(_args(tmp_path)) == 0
    assert len(calls) == 1                       # the first push really sends
    for _ in range(3):
        assert cli.cmd_push(_args(tmp_path)) == 0
    assert len(calls) == 1                       # unchanged: no token, no store
    assert store.attempts == 1
