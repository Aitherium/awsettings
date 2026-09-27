"""Named presets for a coding agent's USER settings -- and the synced baseline.

    awsettings preset list
    awsettings preset show <name> [--json]
    awsettings preset apply <name> [--dry-run] [--force] [--push]
    awsettings preset pull [--dry-run]                 = awsettings --user pull

A preset is a small, reviewed table of the PORTABLE keys of ``~/.claude/settings.json``
plus key bindings for ``~/.claude/keybindings.json``. Applying one merges it in:

* **It never clobbers.** A key the user already set to something else is KEPT and
  reported; ``--force`` is the only way a preset replaces a user value. Objects fill
  in missing leaves, arrays gain the missing items, and a keybinding the user bound to
  another action stays theirs.
* **Some keys can never be written, not even with --force.** ``autoMode``, ``hooks``,
  ``env``, ``permissions`` (``defaultMode`` included), credential helpers, and a
  ``statusLine`` command. Each one either runs code, widens what an agent may do
  unasked, or carries a secret; a preset that names one is refused WHOLE (exit 1) and
  nothing is written -- a half-applied preset is a preset nobody can reason about.
* **Everything else not on the portable list is refused too.** The list is an
  allowlist, so a key added to a preset by mistake fails loudly instead of shipping.
* **The file is backed up first, and the diff is printed.**

THE BASELINE IS THE USER SYNC. ``preset apply --push`` is ``apply`` followed by
``awsettings --user push``: the portable preset keys are in the claude domain's synced
set, so they land in the ``claude_user`` namespace next to the user-level permissions
-- one blob, not a second baseline the plain push would disagree with. ``preset pull``
is ``awsettings --user pull``, whose strict inbound refuses ``autoMode``, ``env``,
``statusLine``, ``permissions.defaultMode`` and unmarked hooks on arrival. A
marketplace sourced from a local directory never leaves the machine and is never
replaced by a remote copy. ``voice`` and the key bindings are applied per machine by
the preset, not synced (``voice`` is a HOME key of the claude domain).

Exit **0** applied (or nothing to do) - **1** refused - **2** could not judge (an
unreadable settings file, an unknown preset, an unreachable profile).
"""
from __future__ import annotations

import copy
import difflib
import json
import shutil
import time
from pathlib import Path
from typing import Any

from .core import SECRET_KEYS
from .domains import USER_NAMESPACE
from .store import read_json, user_claude_dir, write_json

# --------------------------------------------------------------------------- tables

#: Top-level settings keys a preset (or an arriving baseline) may carry. An allowlist:
#: anything else is refused, never guessed at.
PORTABLE_KEYS = frozenset({
    "voice",
    "language",
    "fallbackModel",
    "inputNeededNotifEnabled",
    "crossSessionInbound",
    "footerLinksRegexes",
    "spinnerTipsOverride",
    "outputStyle",
    "enabledPlugins",
    "extraKnownMarketplaces",
})

#: Keys that are NEVER written, even with --force. Named explicitly (they are also
#: absent from PORTABLE_KEYS) so the refusal says WHY rather than "not portable".
NEVER_KEYS = frozenset({
    "autoMode",       # Claude Code reads it from user/managed settings: widens autonomy
    "hooks",          # runs arbitrary commands on every tool call
    "env",            # arbitrary values, routinely tokens
    "permissions",    # allow rules and permissions.defaultMode
    "statusLine",     # a command the harness runs
    "credentials",
    "sandbox",        # carries sandbox.credentials
}) | SECRET_KEYS

#: The hub namespace the user-level baseline lives in (``awsettings --user push``).
NAMESPACE = USER_NAMESPACE

PRESETS: dict[str, dict[str, Any]] = {
    "aitherium-claude": {
        "summary": "voice dictation, English, a sonnet fallback, cross-session inbox, "
                   "PR links in the footer, aw* spinner tips, the aither output style, "
                   "and the awsh plugin from the public awdk repo",
        "settings": {
            "voice": {"enabled": True, "mode": "tap"},
            "language": "english",
            "fallbackModel": ["sonnet"],
            "inputNeededNotifEnabled": True,
            "crossSessionInbound": "accept",
            # `owner/repo#123` -> that PR. Generic on purpose: a preset that ships
            # publicly may not name one org's private repo, and a machine that wants
            # bare `PR #123` links to its own repo already has that entry (kept,
            # never clobbered) and carries it to its other machines as the baseline.
            "footerLinksRegexes": [{
                "type": "regex",
                "pattern": r"\b(?<repo>[\w.-]+/[\w.-]+)#(?<n>\d+)\b",
                "url": "https://github.com/{repo}/pull/{n}",
                "label": "{repo}#{n}",
            }],
            "spinnerTipsOverride": {
                "label": "aw",
                "tips": [
                    {"id": "awgraph", "cooldownSessions": 3,
                     "text": "awgraph callers <fn> -- who calls it, from the local index"},
                    {"id": "awm", "cooldownSessions": 3,
                     "text": "awm recall --query <q> -- facts the last session left"},
                    {"id": "awrelay", "cooldownSessions": 3,
                     "text": "awrelay send '#agents' \"...\" --kind finding -- tell the "
                             "other sessions"},
                    {"id": "awgit", "cooldownSessions": 3,
                     "text": "awgit lease acquire <paths> before editing shared files"},
                    {"id": "voice", "cooldownSessions": 5,
                     "text": "Tap Space on an empty prompt to dictate; tap again to send"},
                ],
            },
            "outputStyle": "aither",
            "enabledPlugins": {"awsh@awsh": True},
            "extraKnownMarketplaces": {
                "awsh": {"source": {
                    "source": "github",
                    "repo": "Aitherium/awdk",
                    "path": "adk/harnesses/claude_mod/.claude-plugin/marketplace.json",
                    "sparsePaths": ["adk/harnesses/claude_mod"],
                }},
            },
        },
        "keybindings": [
            {"context": "Chat", "bindings": {"ctrl+alt+v": "voice:pushToTalk"}},
        ],
    },
}


# --------------------------------------------------------------------------- paths

def claude_dir() -> Path:
    """Claude Code's user config dir; it honours CLAUDE_CONFIG_DIR, so this does --
    the same function the `--user` sync resolves, so apply and push agree."""
    return user_claude_dir()


def settings_path() -> Path:
    return claude_dir() / "settings.json"


def keybindings_path() -> Path:
    return claude_dir() / "keybindings.json"


# --------------------------------------------------------------------------- rules

def refused_paths(preset: dict[str, Any]) -> list[str]:
    """Every part of ``preset`` that may not be written, as ``path: reason``.
    Empty means the preset is writable. Pure."""
    problems: list[str] = []
    settings = preset.get("settings") or {}
    if not isinstance(settings, dict):
        return ["settings: not an object"]
    for key in sorted(settings):
        if key in NEVER_KEYS:
            problems.append(f"{key}: never written by a preset (runs code, widens "
                            f"autonomy, or carries a credential)")
        elif key not in PORTABLE_KEYS:
            problems.append(f"{key}: not a portable user key")
    perms = settings.get("permissions")
    if isinstance(perms, dict) and "defaultMode" in perms:
        problems.append("permissions.defaultMode: never written by a preset")
    bindings = preset.get("keybindings") or []
    if not isinstance(bindings, list):
        problems.append("keybindings: not a list")
        bindings = []
    for i, block in enumerate(bindings):
        if not isinstance(block, dict) or not isinstance(block.get("context"), str) \
                or not isinstance(block.get("bindings"), dict):
            problems.append(f"keybindings[{i}]: needs a context and a bindings object")
            continue
        for chord, action in block["bindings"].items():
            if action is not None and not isinstance(action, str):
                problems.append(f"keybindings[{i}].{chord}: action must be a string")
    return problems


#: Objects whose ENTRIES are records, merged whole or not at all. A marketplace
#: filled leaf by leaf became `{"source": "directory", "path": ..., "repo": ...}` --
#: valid JSON, a broken marketplace (measured on the first live dry-run).
_RECORD_MAPS = frozenset({"extraKnownMarketplaces"})


def _item_id(x: Any) -> Any:
    return x.get("id") if isinstance(x, dict) else None


def _fill(local: Any, want: Any, force: bool, path: str, kept: list[str]) -> Any:
    """``want`` merged into ``local`` without replacing a user value (unless force)."""
    if isinstance(local, dict) and isinstance(want, dict):
        out = copy.deepcopy(local)
        atomic = path in _RECORD_MAPS
        for k, v in want.items():
            sub = f"{path}.{k}" if path else str(k)
            if k not in local:
                out[k] = copy.deepcopy(v)
            elif atomic:
                if local[k] != v:
                    if force:
                        out[k] = copy.deepcopy(v)
                    else:
                        kept.append(sub)
            else:
                out[k] = _fill(local[k], v, force, sub, kept)
        return out
    if isinstance(local, list) and isinstance(want, list):
        if force:
            return copy.deepcopy(want)
        # Items carrying an `id` (spinner tips) are the same item when the id matches,
        # even if the user reworded it: add a second copy and the tip shows twice.
        ids = {_item_id(x) for x in local} - {None}
        return copy.deepcopy(local) + [copy.deepcopy(x) for x in want
                                       if x not in local and _item_id(x) not in ids]
    if local == want:
        return local
    if force:
        return copy.deepcopy(want)
    kept.append(path)
    return local


def merge_settings(local: dict[str, Any], want: dict[str, Any], *,
                   force: bool = False) -> tuple[dict[str, Any], list[str]]:
    """(merged, kept-paths). Never mutates either input."""
    kept: list[str] = []
    return _fill(local, want, force, "", kept), kept


def merge_keybindings(local: dict[str, Any], want: list[dict[str, Any]], *,
                      force: bool = False) -> tuple[dict[str, Any], list[str]]:
    """Add each wanted chord to its context block. A chord the user bound to another
    action is kept (and reported) unless force."""
    out = copy.deepcopy(local) if local else {}
    blocks = out.setdefault("bindings", [])
    kept: list[str] = []
    for block in want:
        ctx = block["context"]
        mine = next((b for b in blocks if isinstance(b, dict)
                     and b.get("context") == ctx), None)
        if mine is None:
            blocks.append(copy.deepcopy(block))
            continue
        table = mine.setdefault("bindings", {})
        for chord, action in block["bindings"].items():
            if chord not in table or force:
                table[chord] = action
            elif table[chord] != action:
                kept.append(f"{ctx}.{chord}")
    return out, kept


# --------------------------------------------------------------------------- apply

def _backup(path: Path) -> Path | None:
    if not path.is_file():
        return None
    stamp = time.strftime("%Y%m%dT%H%M%S")
    dest = path.with_name(f"{path.name}.awsettings-bak-{stamp}")
    n = 1
    while dest.exists():
        dest = path.with_name(f"{path.name}.awsettings-bak-{stamp}-{n}")
        n += 1
    shutil.copy2(path, dest)
    return dest


def _masked(data: dict[str, Any]) -> dict[str, Any]:
    """A never-written key is never CHANGED by an apply, so its value adds nothing to
    the diff -- and ``env`` routinely holds a token. Name it, never print it."""
    return {k: ("<not shown>" if k in NEVER_KEYS else v) for k, v in data.items()}


def _diff(path: Path, before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    a = json.dumps(_masked(before), indent=2, ensure_ascii=False).splitlines()
    b = json.dumps(_masked(after), indent=2, ensure_ascii=False).splitlines()
    return list(difflib.unified_diff(a, b, f"{path} (before)", f"{path} (after)",
                                     lineterm=""))


def apply_preset(preset: dict[str, Any], *, dry_run: bool = False, force: bool = False,
                 out=print) -> int:
    """Apply ``preset`` to the user files. Returns the exit code (see module doc)."""
    problems = refused_paths(preset)
    if problems:
        out("REFUSED: nothing was written")
        for p in problems:
            out(f"  x {p}")
        return 1
    plan = []
    s_path = settings_path()
    s_local = read_json(s_path)          # raises CouldNotRunError on a malformed file
    s_new, s_kept = merge_settings(s_local, preset.get("settings") or {}, force=force)
    plan.append((s_path, s_local, s_new, s_kept))
    if preset.get("keybindings"):
        k_path = keybindings_path()
        k_local = read_json(k_path)
        k_new, k_kept = merge_keybindings(k_local, preset["keybindings"], force=force)
        plan.append((k_path, k_local, k_new, k_kept))

    changed = 0
    for path, before, after, kept in plan:
        for k in kept:
            out(f"kept (yours): {path.name}: {k}  -- --force to replace it")
        if before == after:
            out(f"in step: {path}")
            continue
        changed += 1
        for ln in _diff(path, before, after):
            out(ln)
        if dry_run:
            out(f"would write {path}")
            continue
        bak = _backup(path)
        if bak is not None:
            out(f"backup: {bak}")
        write_json(path, after)
        out(f"wrote {path}")
    if not changed:
        out("nothing to do")
    return 0


# --------------------------------------------------------------------------- CLI

def add_arguments(p) -> None:
    p.add_argument("action", choices=["list", "show", "apply", "pull"])
    p.add_argument("name", nargs="?", help="preset name (show / apply)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="replace user values that differ (never the refused keys)")
    p.add_argument("--push", action="store_true",
                   help="after apply, make the result the synced claude_user baseline")
    p.add_argument("--json", action="store_true")


def _sync(args, verb: str) -> int:
    """The baseline IS the user-level claude sync: `awsettings --user push|pull`, the
    `claude_user` namespace. One blob, one set of rules -- a second namespace for
    presets would be a second baseline that the plain push silently disagrees with."""
    from .cli import main
    argv = ["--user"]
    for flag in ("url", "profile"):
        if getattr(args, flag, None):
            argv += [f"--{flag}", getattr(args, flag)]
    if getattr(args, "quiet", False):
        argv.append("--quiet")
    argv.append(verb)
    if args.dry_run:
        argv.append("--dry-run")
    return main(argv)


def cmd_preset(args) -> int:
    action = args.action
    if action == "list":
        for name, p in sorted(PRESETS.items()):
            print(f"{name}  -- {p['summary']}")
        return 0
    if action == "pull":
        return _sync(args, "pull")
    if not args.name:
        print(f"preset {action} needs a name; known: {', '.join(sorted(PRESETS))}")
        return 2
    preset = PRESETS.get(args.name)
    if preset is None:
        print(f"unknown preset {args.name!r}; known: {', '.join(sorted(PRESETS))}")
        return 2
    if action == "show":
        body = {"settings": preset["settings"], "keybindings": preset.get("keybindings", [])}
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0
    rc = apply_preset(preset, dry_run=args.dry_run, force=args.force)
    if rc != 0 or not args.push:
        return rc
    return _sync(args, "push")
