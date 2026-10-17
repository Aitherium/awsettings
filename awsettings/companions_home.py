"""A wiped machine gets its companions back: roster folders, then memories.

The ``companions`` index travels (``domains.COMPANIONS``); the roster folders it
describes do not. After a pull, every indexed companion with no folder on this
machine is recreated BODILESS -- a ``character.json`` pinning its persona_id,
display name and the ``companion`` marker the desk admits a bodiless member by --
and this module says, per companion, whether its memories can come back:

* the record names ``backup_repo`` -> print the exact ``awrtifact
  companion-restore`` command, or run the restore when ``--restore-memories`` is
  passed and the passphrase variable is set;
* no ``backup_repo`` -> say plainly it was never backed up.

Rules that hold on every path:

- a folder that belongs to ANOTHER persona_id (or holds files but no
  ``character.json``, or an unreadable one) is refused, never overwritten -- the
  same contract as the card importer's roster writer;
- the passphrase is read from the environment only, handed to the restore, and
  never printed, stored, or put on a command line (a subprocess inherits it);
- persona text is never written here: it is restored with the memories.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from .domains import _RECORD_ID, COMPANION_FIELDS, _roster_of

#: The env var awrtifact reads the backup passphrase from (its
#: ``DEFAULT_PASSPHRASE_ENV``). Mirrored, not imported: awrtifact is optional here.
PASSPHRASE_ENV = "AWRTIFACT_COMPANION_PASSPHRASE"

Out = Callable[[str], None]


class RosterConflictError(ValueError):
    """The roster folder exists and is not this companion's."""


def restore_command(persona_id: str, repo: str) -> str:
    """The command that brings one companion's memories back. Both values were held
    to the travelling-field shapes, so neither can carry shell syntax."""
    return f"awrtifact companion-restore {persona_id} --repo {repo}"


def _valid(rec: dict, name: str) -> str:
    value = rec.get(name)
    pattern = COMPANION_FIELDS.get(name)
    if not isinstance(value, str) or (pattern is not None and not pattern.fullmatch(value)):
        return ""
    return value


def _existing_owner(folder: Path) -> str | None:
    """The persona_id a folder belongs to; None when it is free to take.

    Raises RosterConflictError when it cannot be proven free or this one's."""
    cj = folder / "character.json"
    if cj.exists():
        try:
            data = json.loads(cj.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RosterConflictError(f"{folder} has an unreadable character.json "
                                      f"({exc.__class__.__name__}); refusing to touch it")
        if not isinstance(data, dict):
            raise RosterConflictError(f"{folder} character.json is not an object; "
                                      "refusing to touch it")
        return str(data.get("persona_id") or "")
    if folder.is_dir() and any(folder.iterdir()):
        raise RosterConflictError(f"{folder} holds files but no character.json; "
                                  "refusing to take it")
    return None


def write_bodiless_entry(roster_dir: Path, rec: dict) -> Path:
    """Write ``<roster>/<folder>/character.json`` for one indexed companion.

    Raises RosterConflictError when the folder is another persona's."""
    pid = _valid(rec, "persona_id")
    if not pid:
        raise RosterConflictError("record has no valid persona_id")
    folder = Path(roster_dir) / (_valid(rec, "folder") or pid)
    owner = _existing_owner(folder)
    if owner is not None and owner != pid:
        raise RosterConflictError(f"{folder} belongs to persona_id {owner!r}, not "
                                  f"{pid!r}; refusing to overwrite it")
    if owner == pid:
        return folder
    record = {
        "persona_id": pid,
        "display_name": str(rec.get("display_name") or pid)[:128],
        # An absent `source` reads as unjudged: a body added later starts hidden
        # until the rater looks, exactly as for a fresh import.
        "rating": "unknown",
        "companion": {
            "source_format": str(rec.get("source_format") or "")[:40],
            "untrusted_source": True,
            "avatar": None,
            "restored_by": "awsettings",
        },
    }
    folder.mkdir(parents=True, exist_ok=True)
    tmp = folder / "character.json.tmp"
    tmp.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, folder / "character.json")
    return folder


def run_restore(persona_id: str, repo: str, passphrase: str) -> dict:
    """Restore one companion's memories. In-process when awrtifact imports, else
    the ``awrtifact`` CLI with the passphrase left in the inherited environment.

    Raises RuntimeError with a message that never carries the passphrase."""
    try:
        from awrtifact import companion as _companion
    except ImportError:
        exe = shutil.which("awrtifact")
        if not exe:
            raise RuntimeError("awrtifact is not installed here") from None
        proc = subprocess.run([exe, "companion-restore", persona_id, "--repo", repo,
                               "--passphrase-env", PASSPHRASE_ENV],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"awrtifact companion-restore exited {proc.returncode}") from None
        return {}
    try:
        return _companion.restore(persona_id, repo, passphrase, log=lambda _m: None)
    except Exception as exc:                                  # noqa: BLE001
        # awrtifact's errors never carry the passphrase; the class and message
        # are what the owner needs to act on.
        raise RuntimeError(f"{exc.__class__.__name__}: {exc}") from None


TRUSTED_REPOS_ENV = "AWSETTINGS_TRUSTED_BACKUP_REPOS"


def trusted_repos(cli: object = None) -> set:
    """Backup repos this machine's owner named, by flag or env -- never the synced index.

    The index's backup_repo is remote data: a sync profile someone else controls could
    point a companion at their repo. Decryption with the owner's passphrase already
    defeats a forged archive, but an automatic restore must not even fetch from a repo
    the owner did not name (review of #13230, 2026-10-17).
    """
    names = [r for r in (os.environ.get(TRUSTED_REPOS_ENV, "") or "").split(",")]
    if isinstance(cli, (list, tuple)):
        names.extend(str(r) for r in cli)
    return {r.strip().lower() for r in names if r and r.strip()}


def reconcile(index: dict, *, dry_run: bool = False, restore_memories: bool = False,
              quiet: bool = False, out: Out = print, trusted: object = None) -> int:
    """Recreate missing roster folders for ``index`` and report memory status.

    Exit 0 done (or nothing to do) · 1 a folder belongs to another persona ·
    2 a requested memory restore could not run.
    """
    companions = index.get("companions") if isinstance(index.get("companions"), dict) else {}
    records = {pid: rec for pid, rec in sorted(companions.items())
               if isinstance(rec, dict) and _RECORD_ID.fullmatch(str(pid))
               and _valid(rec, "persona_id") == pid}
    if not records:
        return 0
    roster = _roster_of(index)
    if not roster:
        if not quiet:
            out(f"note: {len(records)} companion(s) indexed but no roster dir is known "
                "here; set DESK_ROSTER_DIR and pull again to recreate them")
        return 0
    roster_dir = Path(roster).expanduser()
    passphrase = os.environ.get(PASSPHRASE_ENV, "") if restore_memories else ""
    rc = 0
    for pid, rec in records.items():
        folder = roster_dir / (_valid(rec, "folder") or pid)
        try:
            owner = _existing_owner(folder)
        except RosterConflictError as exc:
            out(f"REFUSED {pid}: {exc}")
            rc = max(rc, 1)
            continue
        if owner is not None and owner != pid:
            out(f"REFUSED {pid}: {folder} belongs to persona_id {owner!r}; not overwritten")
            rc = max(rc, 1)
            continue
        created = owner is None
        if created:
            if dry_run:
                out(f"would recreate {pid}: {folder} (bodiless)")
            else:
                write_bodiless_entry(roster_dir, rec)
                out(f"recreated {pid}: {folder} (bodiless)")
        elif not restore_memories:
            if not quiet:
                out(f"{pid}: roster folder present")
            continue
        repo = _valid(rec, "backup_repo")
        if not repo:
            out(f"  {pid}: memories NOT backed up -- nothing to restore "
                f"(back up with `awrtifact companion-backup {pid} --repo OWNER/NAME`)")
            continue
        tag = _valid(rec, "last_backup_tag")
        where = f"{repo}" + (f" (last backup {tag})" if tag else "")
        cmd = restore_command(pid, repo)
        if not restore_memories or dry_run:
            out(f"  {pid}: memories restorable from {where}: run `{cmd}`")
            continue
        if repo.lower() not in trusted_repos(trusted):
            out(f"  {pid}: memories restorable from {where}, but that repo is not one you "
                f"named; pass --trust-repo {repo} (or set ${TRUSTED_REPOS_ENV}) to restore "
                f"automatically, or run `{cmd}`")
            continue
        if not passphrase:
            out(f"  {pid}: memories restorable from {where}; set ${PASSPHRASE_ENV} "
                f"and re-run with --restore-memories, or run `{cmd}`")
            continue
        try:
            report = run_restore(pid, repo, passphrase)
        except RuntimeError as exc:
            out(f"  {pid}: memory restore FAILED ({exc}); retry with `{cmd}`")
            rc = max(rc, 2)
            continue
        added = report.get("rows_added") if isinstance(report, dict) else None
        out(f"  {pid}: memories restored from {where}"
            + (f" (+{added} rows)" if isinstance(added, int) else ""))
    return rc
