"""The autonomy half: run the sync when a session opens, not when someone remembers.

**Not a daemon, on purpose.** A background process is a second thing to keep
alive on every surface this exists to stop hand-maintaining — and when it dies
it dies quietly, which is the same failure as the drift it was meant to fix.
A hook runs at a moment that already exists, has an owner, and is visible in the
config file it lives in.

Two hooks, and the split matters:

* **SessionStart -> pull.** The moment a new machine, shell or container opens a
  session is exactly when its settings are most likely to be stale, and it is
  before any tool call has been refused.
* **A settings write -> push.** Debounced, fail-soft. The trigger is the file
  actually changing, so a rule you approve on one machine is on its way to the
  others before you have finished the thought.

Both are installed INTO the settings file the harness already reads, and both
are idempotent: installing twice leaves one hook, because a hook that
accumulates copies is a hook that eventually runs N times per event.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .store import read_json, write_json

#: Marker that identifies OUR hook entries. Matching on the command string alone
#: would fail the moment the command is reworded; a marker key survives that and
#: makes removal exact rather than best-effort.
MARKER = "awsettings"

#: `--quiet` is a GLOBAL option and argparse only accepts it BEFORE the verb.
#: Measured 2026-09-21: the previous `awsettings pull --quiet` form exited 2
#: ("unrecognized arguments: --quiet") on every SessionStart and every PostToolUse
#: since install, and `|| true` hid it -- the sync never ran once. Pinned by
#: test_hook_commands_parse.
PULL_ARGS = ["--quiet", "--never-fail", "pull"]
PUSH_ARGS = ["--quiet", "--never-fail", "push", "--debounce"]
#: Display forms (and what a shell would run). The hooks themselves are EXEC form.
PULL_COMMAND = "awsettings " + " ".join(PULL_ARGS)
PUSH_COMMAND = "awsettings " + " ".join(PUSH_ARGS)

#: `--never-fail` replaces the old `|| true`. A settings sync must never be able
#: to fail a session open or a tool call: offline is the normal state of a
#: laptop, and the correct behaviour offline is to keep the local file and carry
#: on. It used to take a SHELL to say that, and the push hook runs after EVERY
#: tool call: on Windows a shell-form hook starts Git's bash launcher, bash and a
#: console host before awsettings itself -- measured 2026-10-18, 4 processes per
#: hook, and process churn on that host fed a kernel token leak. Exec form
#: ("command" + "args") starts awsettings directly; the flag keeps it fail-soft.


def _entry(args: list[str], status_message: str) -> dict[str, Any]:
    return {
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": "awsettings",
            "args": list(args),
            "timeout": 20,
            "statusMessage": status_message,   # harness schema key: camelCase is theirs
            MARKER: True,
        }],
    }


def _is_ours(group: dict[str, Any]) -> bool:
    return any(h.get(MARKER) for h in group.get("hooks", []) if isinstance(h, dict))


def _routed(group: dict[str, Any]) -> bool:
    """Our hook, already folded into a resident hook runner's http hook (awdk hookd runs
    console scripts in-process as `ep:awsettings...`). Re-adding a command copy beside it
    would run the sync twice per tool call."""
    return any(isinstance(h, dict) and h.get("type") == "http"
               and "ep%3Aawsettings" in str(h.get("url", "")) for h in group.get("hooks", []))


def plan(settings: dict[str, Any]) -> dict[str, Any]:
    """Return settings with our two hooks installed exactly once. Pure."""
    import copy
    out = copy.deepcopy(settings)
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise TypeError("settings.hooks is not an object")

    for event, args, msg in (
        ("SessionStart", PULL_ARGS, "Syncing agent settings..."),
        ("PostToolUse", PUSH_ARGS, "Pushing agent settings..."),
    ):
        groups = [g for g in hooks.get(event, []) if isinstance(g, dict)]
        # Drop any previous copy of ours before adding, so install is idempotent
        # and a reworded command replaces rather than accumulates.
        groups = [g for g in groups if not _is_ours(g)]
        if not any(_routed(g) for g in groups):
            groups.append(_entry(args, msg))
        hooks[event] = groups
    return out


def uninstall(settings: dict[str, Any]) -> dict[str, Any]:
    """Remove only our entries, leaving every other hook untouched."""
    import copy
    out = copy.deepcopy(settings)
    hooks = out.get("hooks")
    if not isinstance(hooks, dict):
        return out
    for event in list(hooks):
        groups = [g for g in hooks.get(event, [])
                  if isinstance(g, dict) and not _is_ours(g)]
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if not hooks:
        out.pop("hooks", None)
    return out


def installed(settings: dict[str, Any]) -> list[str]:
    """Which events currently carry our hook."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return []
    return sorted(ev for ev, groups in hooks.items()
                  if any(_is_ours(g) or _routed(g) for g in groups if isinstance(g, dict)))


def install_to(path: Path) -> tuple[Path, list[str]]:
    data = read_json(path)
    write_json(path, plan(data))
    return path, installed(read_json(path))


def uninstall_from(path: Path) -> tuple[Path, list[str]]:
    data = read_json(path)
    write_json(path, uninstall(data))
    return path, installed(read_json(path))
