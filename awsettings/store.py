"""Where settings live on disk, and how they are written.

Two decisions here are load-bearing and easy to get wrong in the direction that
looks tidier.

**It writes `settings.local.json`, never `settings.json`.** The project file is
committed and shared. Syncing one person's permission allowlist into it hands
everyone else rules they never approved, in a file that code review reads as
policy. `settings.local.json` is gitignored and personal — exactly the scope of
"my settings follow me".

**Writes are atomic.** The harness watches this file. A half-written file is
briefly invalid JSON, and invalid JSON does not disable the setting being
changed — it disables EVERY setting in the file, silently, until the next write.
A rename is the only way to make the new content appear in one step.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

#: The personal, gitignored settings file. See the module docstring.
LOCAL_SETTINGS = Path(".claude") / "settings.local.json"

#: The committed, shared one. Read for context, NEVER written by a sync.
PROJECT_SETTINGS = Path(".claude") / "settings.json"

#: User-level settings, outside any project.
USER_SETTINGS = Path(".claude") / "settings.json"   # under $HOME


class CouldNotRunError(Exception):
    """No verdict is possible. Callers exit 2, never 0."""


def read_json(path: Path) -> dict[str, Any]:
    """The file, or {} when absent.

    A malformed file RAISES rather than reading as empty. Treating unparseable
    settings as "no settings" is how a sync cheerfully overwrites a file
    somebody was in the middle of editing.
    """
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CouldNotRunError(f"cannot read {path}: {exc}") from exc
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CouldNotRunError(
            f"{path} is not valid JSON ({exc}). Refusing to overwrite it — an "
            f"unparseable settings file is far more likely a half-finished edit "
            f"than an empty one.") from exc
    if not isinstance(data, dict):
        raise CouldNotRunError(f"{path} is valid JSON but not an object")
    return data


def write_json(path: Path, data: dict[str, Any]) -> Path:
    """Atomic write. See the module docstring for why a plain write is unsafe."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)
    return path


def local_settings_path(root: Path | None = None) -> Path:
    """The file a pull writes: project-scoped when given a root, else user-level."""
    if root is not None:
        return root / LOCAL_SETTINGS
    return Path.home() / USER_SETTINGS
