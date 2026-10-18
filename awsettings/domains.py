"""What is being synced. One merge engine, more than one settings file.

This package began as a sync for ONE file: a coding agent's personal settings. The
three rules it enforces (credentials stay home, arrays union, a deny is one-way) are
not about that file, though -- they are about any config edited from more than one
machine. A **domain** is the small table that tells the engine how to apply them to
a particular file: where it lives, which keys travel, which stay home, which arrays
union.

Six domains ship:

* ``claude`` -- the coding agent's ``settings.local.json``. The original behaviour,
  bit for bit; it is the default so nothing that already calls this package moves.
* ``desk``   -- a desktop avatar's ``cast.json``: who gets a body, which voice, how
  fast, **how loud**, where they stand. It is a plain JSON file the desktop app
  watches, so a pull lands live with no restart.

* ``mods``   -- ``~/.aither/mods.json``: which harness, backend and model a coding
  agent's `aw` subagent runs on when the prompt does not say. The Claude Code mod
  reads it on every spawn, so a pull changes the next spawn with no restart.

* ``memory`` -- ``~/.aither/memory-lander/config.json``: which targets the memory
  lander writes, its index budget, the Strata prefix bundles are pushed under, and
  per project the latest sealed bundle's digest and the PUBLIC key that sealed it.
  That is what a new machine needs to pull this owner's memory back and REFUSE a
  bundle sealed by anyone else. A public key is meant to be published; the private
  signing key is a file this domain never names.

* ``companions`` -- ``~/.aither/companions.json``: which imported companions this
  owner has brought into awdesk's roster -- persona_id, display name, source format
  and roster folder name per companion, plus where its encrypted memory backup
  lives (repo + last tag, never the passphrase). Union on pull, never a delete; a
  pull recreates each missing roster folder bodiless and says how to restore its
  memories. Persona text and memories never travel here (they go through the
  encrypted companion backup); the record filter refuses them in both directions,
  and the machine-local roster path stays home.

* ``aitherzero`` -- AitherZero's gitignored ``config.local.psd1``. Not merged: it is
  PowerShell data kept as opaque text, one copy PER HOST, so a dead machine's
  overrides can be pulled onto its replacement with ``pull --host <old-name>``.
  Nothing named "stays home" here; a credential-shaped line refuses the whole
  file instead, in both directions (``hostfile.secret_findings``).

WHY A TABLE AND NOT A SUBCLASS. Every field here is data the self-test can assert
against. A domain that is code can quietly decide a credential is fine to send; a
domain that is a frozen table of names cannot decide anything.

WHAT "STAYS HOME" MEANS. ``home_subkeys`` is wider than credentials on purpose. A
voice endpoint (``127.0.0.1:8084``) is not a secret, but it is a fact about ONE
machine's topology, and syncing it to a laptop with no voice service on that port
turns a working avatar mute with a config that looks correct. Same mechanism, same
guarantee in BOTH directions: never sent, and never accepted on arrival.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .store import local_settings_path


@dataclass(frozen=True)
class Domain:
    """How the three rules apply to one settings file. Frozen: see the module doc."""

    name: str
    #: Key inside the remote object. Distinct per domain so two domains sharing one
    #: profile can never stamp over each other.
    namespace: str
    summary: str
    #: Top-level keys worth syncing. Anything else is left at home rather than
    #: guessed at -- far more likely a local experiment than a preference.
    synced_keys: frozenset
    #: Top-level keys that never leave and are refused on arrival.
    secret_keys: frozenset = frozenset()
    #: ``{top_level_key: {subkey, ...}}`` -- stays home, both directions.
    home_subkeys: dict = field(default_factory=dict)
    #: Array paths that UNION instead of replacing.
    union_arrays: tuple = ()
    #: Last path segments of union arrays a sync may ADD to but never shrink.
    one_way: frozenset = frozenset()
    #: Merge nested objects leaf by leaf. Off for ``claude`` (unchanged behaviour).
    #: On for ``desk``: its records are keyed objects two machines edit different
    #: FIELDS of, and a one-level merge would let machine A's record replace B's
    #: whole -- the replace-semantics loss this package exists to prevent.
    deep: bool = False
    #: Refuse an ARRIVING top-level key that is not in ``synced_keys``. A profile is
    #: only ever written from ``redact()`` output, so an unknown key in one was put
    #: there by something else. Off for ``claude``, whose inbound behaviour predates
    #: this flag and is left exactly as it was.
    strict_inbound: bool = False
    #: Top-level keys holding a harness hooks map. Only entries marked portable
    #: travel, in either direction (``core.portable_hooks``).
    hook_keys: frozenset = frozenset()
    #: Resolves the local file. ``root`` is a project dir, or None for user-level.
    locate: Callable = local_settings_path
    #: Whether the agent-harness hooks make sense for this file.
    hookable: bool = False
    #: The file is OPAQUE text kept one copy per host (``hostfile.py``), never a
    #: JSON object merged key by key. No merge, no redact: a secret scan instead.
    opaque: bool = False
    #: ``{top_level_key: {field: pattern_or_None}}`` -- the key holds a map of
    #: RECORDS (``{id: {field: str}}``) and only these string fields of a record
    #: travel, in both directions; a field with a pattern must fullmatch it. A
    #: record id must be a safe token (no path separators), a record that is not an
    #: object is dropped, and so is any field not named here (``core.filter_records``).
    #: This is how ``companions`` guarantees persona text never rides a profile even
    #: when a peer puts it there.
    record_fields: dict = field(default_factory=dict)
    #: Rebuilds the local file from the source it mirrors, right before a push
    #: (``companions``: a scan of the roster dir). Writes only the LOCAL file; what
    #: leaves still goes through ``redact``. Never deletes a record.
    refresh: Callable | None = None
    #: What ``refresh`` WOULD leave in the local file, computed without writing it
    #: -- so ``push --dry-run`` shows what would travel after the scan.
    refresh_preview: Callable | None = None
    #: Runs after a pull merged the index: ``after_pull(merged, args) -> exit code``
    #: (``companions``: recreate missing roster folders, say how to get memories
    #: back). ``args.dry_run`` means report, write nothing.
    after_pull: Callable | None = None


def _desk_user_data() -> Path:
    """Where the desktop app keeps its state -- the app's own rule, mirrored.

    Mirrored, not imported: the app is not a Python package. If the app's name ever
    changes this reads an empty file while the app reads a full one, which is why
    ``AWSETTINGS_DESK_FILE`` exists and why `status` prints the resolved path.
    """
    name = "Desk"
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Roaming") / name
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / name
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / name


def desk_cast_path(root: Path | None = None) -> Path:
    """The cast file. ``root`` is ignored: this file is per USER, not per project.

    ``DESK_CAST_FILE`` is honoured because the desktop app honours it -- two tools
    that disagree about which file is live is the drift this package is for.
    """
    for var in ("AWSETTINGS_DESK_FILE", "DESK_CAST_FILE"):
        override = (os.environ.get(var) or "").strip()
        if override:
            return Path(override).expanduser().resolve()
    return _desk_user_data() / "cast.json"


# Imported late and by name so `core` stays the single home of the claude tables
# that existing callers and tests already import from there.
def _claude() -> Domain:
    from . import core
    return Domain(
        name="claude",
        namespace="awsettings",
        summary="a coding agent's personal settings.local.json",
        synced_keys=core.SYNCED_KEYS,
        secret_keys=core.SECRET_KEYS,
        home_subkeys=dict(core.HOME_SUBKEYS),
        union_arrays=core.UNION_ARRAYS,
        one_way=frozenset({"deny", "ask"}),
        deep=False,
        # Strict since 0.3.3: a profile is only ever written from redact() output,
        # so an arriving `statusLine`, `autoMode` or `sshConfigs` was put there by
        # something else -- and each one is a command, a path or a safety posture.
        strict_inbound=True,
        hook_keys=frozenset({"hooks"}),
        locate=local_settings_path,
        hookable=True,
    )


#: The hub namespace for USER-level claude settings (``--user``). Separate from
#: every project's: user rules apply in every repo, project rules in one.
USER_NAMESPACE = "claude_user"

#: Env override for the project identity, for a checkout whose remote cannot say.
PROJECT_ENV = "AWSETTINGS_PROJECT"


def _normalise_remote(url: str) -> str:
    """``git@github.com:Org/Repo.git`` and ``https://tok@github.com/org/repo`` -> the
    same ``github.com/org/repo``. Credentials in a remote URL never reach the id."""
    u = url.strip()
    if "://" in u:
        u = u.split("://", 1)[1]
        if "@" in u.split("/", 1)[0]:
            u = u.split("@", 1)[1]
    elif "@" in u and ":" in u:
        u = u.split("@", 1)[1].replace(":", "/", 1)
    u = u.rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    return u.lower()


def project_id(root: Path) -> str:
    """Which project a settings file belongs to, stable across machines.

    The origin remote when there is one (two clones of one repo on two machines
    agree), else the directory name. Never the absolute path: that differs per box.
    """
    override = (os.environ.get(PROJECT_ENV) or "").strip()
    if override:
        return override.lower()
    import subprocess
    try:
        done = subprocess.run(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, encoding="utf-8", timeout=5, check=False)
        remote = (done.stdout or "").strip() if done.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        remote = ""
    if remote:
        return _normalise_remote(remote)
    return "dir:" + Path(root).resolve().name.lower()


def claude_namespace(root: Path | None) -> str:
    """The hub namespace for claude settings at ``root`` (None = user level).

    One per project, so a pull in repo B can never merge repo A's allow rules --
    before 0.3.3 every scope shared one ``awsettings`` blob, and a pull in any repo
    merged whatever permissions the last push from any other repo had left there.
    """
    if root is None:
        return USER_NAMESPACE
    import hashlib
    digest = hashlib.sha256(project_id(root).encode("utf-8")).hexdigest()[:12]
    return f"claude_project_{digest}"


DESK = Domain(
    name="desk",
    namespace="awdesk",
    summary="a desktop avatar's cast.json: bodies, voices, volume, presence, "
            "models, prompts, vision",
    synced_keys=frozenset({
        "version", "stage", "voice", "defaults", "authors", "actors", "channels",
        # The desk's own behaviour: which backend its command agent runs on, what
        # it is told, and whether it looks at dropped images.
        "models", "prompts", "vision",
        # `content` is the desk's CEILING (content.maxRating / hideUnrated), not
        # the adult gate. The gate is the platform's two halves -- an explicit
        # opt-in AND age verification -- and nothing that arrives in a profile
        # can open it. A ceiling can only ever hide MORE, so carrying it to the
        # next machine is safe: an r18 ceiling landing on a machine whose gate
        # is shut still shows that machine nothing.
        "content",
        # `appearance` is which of the family's eleven themes the desk wears, and
        # its UI scale. Pure preference, no path and no credential in it -- and the
        # theme ids are validated against the generated list on arrival
        # (cast-config.cjs validateAppearance), so a profile cannot name a theme
        # the receiving build does not have.
        "appearance",
        # `migratedLegacyAt` is deliberately absent: it records that THIS machine
        # folded in its own legacy files. Syncing it would tell a second machine
        # its migration already ran, and it would then never run.
        #
        # `sync` is deliberately absent too, and for a sharper reason: it holds
        # `profile` and `tokenFile`, which are PATHS ON ONE MACHINE. Delivered to
        # another they point at nothing -- or at something. With `strict_inbound`
        # an arriving `sync` is refused as well, so a profile cannot re-point a
        # machine's sync target (and its bearer file) at a server of its choosing.
    }),
    secret_keys=frozenset(),
    home_subkeys={"voice": frozenset({"endpoint"})},
    union_arrays=(),
    one_way=frozenset(),
    deep=True,
    strict_inbound=True,
    locate=desk_cast_path,
    hookable=False,
)


def mods_path(root: Path | None = None) -> Path:
    """The mods file. ``root`` is ignored: it is per USER, like the mod that reads it.

    The mod reads this fixed path and nothing else (a hooks module cannot be handed
    an override), so ``AWSETTINGS_MODS_FILE`` is for tests: a file it names is one
    the mod never sees.
    """
    override = (os.environ.get("AWSETTINGS_MODS_FILE") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".aither" / "mods.json"


MODS = Domain(
    name="mods",
    namespace="awmods",
    summary="a coding agent's mods.json: the default harness, backend and model "
            "its `aw` subagent runs on",
    # `freellmapi` is awdk's non-local route (enabled / url / preferred_models):
    # the user's own FreeLLMAPI proxy, turned on once and followed to every
    # machine. Its credentials never ride here -- provider keys live in the
    # proxy's own encrypted store and the unified key in a local key file -- and
    # any credential-shaped field put there anyway stays home in both directions.
    synced_keys=frozenset({"version", "aw", "freellmapi"}),
    secret_keys=frozenset(),
    # Where the harness daemon listens is one machine's topology, exactly like a
    # voice endpoint: never sent, never accepted on arrival.
    home_subkeys={"aw": frozenset({"daemon"}),
                  "freellmapi": frozenset({"api_key", "unified_key", "key", "token",
                                           "encryption_key", "password",
                                           "allow_remote"})},
    union_arrays=(),
    one_way=frozenset(),
    deep=True,
    strict_inbound=True,
    locate=mods_path,
    hookable=False,
)


def darkmatter_brain_path(root: Path | None = None) -> Path:
    """Darkmatter's brain file: which model each AI role uses. ``root`` is ignored: it is per USER.

    The game reads the same path (``DM_BRAIN_FILE`` overrides it there, ``AWSETTINGS_DARKMATTER_FILE`` here),
    so a test or a second install can point both at one file.
    """
    for var in ("AWSETTINGS_DARKMATTER_FILE", "DM_BRAIN_FILE"):
        override = (os.environ.get(var) or "").strip()
        if override:
            return Path(override).expanduser().resolve()
    return Path.home() / ".aither" / "darkmatter" / "brain.json"


DARKMATTER = Domain(
    name="darkmatter",
    namespace="awdarkmatter",
    summary="Darkmatter's brain.json: which model each AI role uses (the orchestrator brain, its "
            "perception and reasoning tools) and the tools' time budgets",
    # `roles` names MODELS, never hosts: {"gm": {"model": "aither-orchestrator"}, "perception": {...}}.
    # `brain` is the tool budgets (soft budget, perceive / deliberate deadlines) -- preferences, no paths.
    synced_keys=frozenset({"version", "roles", "brain"}),
    secret_keys=frozenset(),
    # `endpoint` is deliberately absent from synced_keys: it holds ONE machine's scheduler URL and CA-file
    # path. With strict_inbound an arriving `endpoint` is refused too, so a profile can never re-point a
    # machine's game -- and every prompt it sends -- at a server of the profile's choosing.
    home_subkeys={},
    union_arrays=(),
    one_way=frozenset(),
    deep=True,
    strict_inbound=True,
    locate=darkmatter_brain_path,
    hookable=False,
)


def memory_config_path(root: Path | None = None) -> Path:
    """The memory lander's config. ``root`` is ignored: it is per USER.

    ``AWSETTINGS_MEMORY_FILE`` is for tests and for a lander run under another
    home; the lander itself reads the default path.
    """
    override = (os.environ.get("AWSETTINGS_MEMORY_FILE") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".aither" / "memory-lander" / "config.json"


MEMORY = Domain(
    name="memory",
    namespace="awmemory",
    summary="the memory lander's config.json: targets, index budget, Strata prefix, "
            "and per project the latest bundle digest + the public key that sealed it",
    # Deliberately absent: anything naming a PATH on this machine (bundles root,
    # state file, signing-key file). Delivered elsewhere a path points at nothing,
    # or at something; strict_inbound refuses one arriving as well.
    synced_keys=frozenset({"version", "targets", "budget", "strata_prefix", "projects"}),
    # Named on purpose although the lander never writes them: if a credential-shaped
    # key is ever added to config.json it stays home rather than riding a profile.
    secret_keys=frozenset({"internal_key", "signing_key", "private_key", "token"}),
    home_subkeys={},
    union_arrays=(),
    one_way=frozenset(),
    # `projects` is keyed by project: two machines each landing a different project
    # must merge per project, never let one machine's map replace the other's.
    deep=True,
    strict_inbound=True,
    locate=memory_config_path,
    hookable=False,
)


#: Env override for the AitherZero per-machine overrides file.
AITHERZERO_FILE_ENV = "AWSETTINGS_AITHERZERO_FILE"
_AITHERZERO_REL = Path(".PRODUCTS") / ".AITHERZERO" / "config" / "config.local.psd1"


def aitherzero_local_path(root: Path | None = None) -> Path:
    """AitherZero's ``config.local.psd1``: gitignored, so it exists on ONE machine.

    Resolution: ``AWSETTINGS_AITHERZERO_FILE``, then ``$AITHERZERO_ROOT/config`` (the
    module exports it on import), then the nearest ``.PRODUCTS/.AITHERZERO`` above
    ``root`` (or the cwd), then the same path under ``root``. The last arm names a file
    that may not exist yet -- which is exactly the fresh-machine pull.
    """
    override = (os.environ.get(AITHERZERO_FILE_ENV) or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    az_root = (os.environ.get("AITHERZERO_ROOT") or "").strip()
    if az_root and (Path(az_root) / "config").is_dir():
        return Path(az_root).expanduser().resolve() / "config" / "config.local.psd1"
    start = Path(root or os.getcwd()).resolve()
    for d in (start, *start.parents):
        if (d / _AITHERZERO_REL).parent.is_dir():
            return d / _AITHERZERO_REL
    return start / _AITHERZERO_REL


AITHERZERO = Domain(
    name="aitherzero",
    namespace="awaitherzero",
    summary="AitherZero's per-machine config.local.psd1, one copy per host "
            "(opaque text; pull --host <name> rebuilds a new machine)",
    # The remote object is {"version", "hosts": {<host>: {text, sha256, ...}}}. The
    # file itself is PowerShell data and is never parsed here: see hostfile.py.
    synced_keys=frozenset({"version", "hosts"}),
    secret_keys=frozenset(),
    home_subkeys={},
    union_arrays=(),
    one_way=frozenset(),
    deep=True,
    strict_inbound=True,
    locate=aitherzero_local_path,
    hookable=False,
    opaque=True,
)


#: Env override for the companions index (the importer honours it too).
COMPANIONS_FILE_ENV = "AWSETTINGS_COMPANIONS_FILE"
_RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
#: The fields of one companion record that may travel. Nothing else, ever. The
#: folder is a roster folder NAME, so it is held to the persona-id shape too.
#: ``backup_repo``/``last_backup_tag`` say WHERE the encrypted memories live (written
#: by ``awrtifact companion-backup``) so a wiped machine can get them back. The
#: passphrase is never a field: it is not in this file on any machine. Both are
#: held to a strict shape because a pull prints them inside a command line.
COMPANION_FIELDS = {"persona_id": _RECORD_ID, "display_name": None,
                    "source_format": None, "folder": _RECORD_ID,
                    "backup_repo": re.compile(
                        r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$"),
                    "last_backup_tag": re.compile(r"^companion-[A-Za-z0-9._-]{1,200}$")}


def companions_index_path(root: Path | None = None) -> Path:
    """The companions index. ``root`` is ignored: it is per USER.

    Written by ``python -m lib.companion.character_cards <card> --roster`` and by
    the pre-push roster scan below; ``AWSETTINGS_COMPANIONS_FILE`` overrides it.
    """
    override = (os.environ.get(COMPANIONS_FILE_ENV) or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".aither" / "companions.json"


def scan_roster_companions(roster_dir: Path) -> dict:
    """``{persona_id: record}`` for every roster folder an imported companion owns:
    a ``character.json`` carrying the ``companion`` object and a valid persona_id.
    Only the travelling fields are read; persona text is never opened."""
    import json
    found: dict = {}
    try:
        entries = sorted(p for p in Path(roster_dir).iterdir() if p.is_dir())
    except OSError:
        return found
    for folder in entries:
        try:
            cj = json.loads((folder / "character.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(cj, dict) or not isinstance(cj.get("companion"), dict):
            continue
        pid = cj.get("persona_id")
        if not isinstance(pid, str) or not _RECORD_ID.match(pid):
            continue
        found[pid] = {
            "persona_id": pid,
            "display_name": str(cj.get("display_name") or pid)[:128],
            "source_format": str(cj["companion"].get("source_format") or "")[:40],
            "folder": folder.name,
        }
    return found


def _roster_of(data: dict) -> str:
    """The roster dir: ``DESK_ROSTER_DIR`` (the desk honours it) or the index's own
    stay-home ``roster_dir``. Empty when neither is known."""
    roster = (os.environ.get("DESK_ROSTER_DIR") or "").strip() or data.get("roster_dir")
    return roster.strip() if isinstance(roster, str) else ""


def preview_companions(target: Path) -> dict:
    """The index at ``target`` with the roster scan unioned in. Writes nothing.

    No roster known = the file as it is. Records already in the index are never
    removed, and fields the scan does not own (where the backup lives) are kept.
    """
    from .store import read_json
    data = read_json(Path(target))
    roster = _roster_of(data)
    if not roster:
        return data
    current = data.get("companions") if isinstance(data.get("companions"), dict) else {}
    merged = dict(current)
    for pid, rec in scan_roster_companions(Path(roster).expanduser()).items():
        prior = current.get(pid) if isinstance(current.get(pid), dict) else {}
        merged[pid] = {**prior, **rec}
    return {**data, "version": data.get("version", 1), "companions": merged}


def refresh_companions(target: Path) -> bool:
    """Union the roster scan into the index at ``target``. True when it changed."""
    from .store import read_json, write_json
    data = read_json(Path(target))
    updated = preview_companions(target)
    if updated == data:
        return False
    write_json(Path(target), updated)
    return True


def _companions_after_pull(merged: dict, args) -> int:
    from .companions_home import reconcile
    return reconcile(merged, dry_run=bool(getattr(args, "dry_run", False)),
                     restore_memories=bool(getattr(args, "restore_memories", False)),
                     quiet=bool(getattr(args, "quiet", False)),
                     trusted=getattr(args, "trust_repo", None))


COMPANIONS = Domain(
    name="companions",
    namespace="awcompanions",
    summary="which imported companions joined awdesk's roster: persona_id, display "
            "name, source format, folder -- metadata only, union, never a delete",
    # `roster_dir` is deliberately absent: a PATH on one machine. strict_inbound
    # refuses one arriving, so a profile cannot re-point a machine's scan.
    synced_keys=frozenset({"version", "companions"}),
    # Never in this file, named anyway: if one ever appears it stays home.
    secret_keys=frozenset({"persona", "persona_text", "instruction", "memories",
                           "memory", "history", "messages"}),
    home_subkeys={},
    union_arrays=(),
    one_way=frozenset(),
    # Keyed by persona_id: two machines that each imported a different companion
    # merge per companion, and a pull can only ADD one (a merge carries no delete).
    deep=True,
    strict_inbound=True,
    locate=companions_index_path,
    hookable=False,
    record_fields={"companions": COMPANION_FIELDS},
    refresh=refresh_companions,
    refresh_preview=preview_companions,
    after_pull=_companions_after_pull,
)


def worktrees_path(root: Path | None = None) -> Path:
    """awgit's worktree-lifecycle settings. ``root`` is ignored: it is per USER.
    ``AWGIT_WT_SETTINGS`` is the same override awgit itself reads."""
    override = (os.environ.get("AWGIT_WT_SETTINGS") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".aither" / "awgit" / "worktrees.json"


WORKTREES = Domain(
    name="worktrees",
    namespace="awworktrees",
    summary="awgit's worktree lifecycle: idle thresholds, per-drive free-space floor, "
            "snapshot cap -- how long an agent checkout lives before it is retired",
    # Deliberately absent: `roots` (PATHS on one machine) and `record_commands`
    # (COMMANDS). strict_inbound refuses either arriving, so a profile can neither
    # re-point a machine's reaper nor make it run something.
    synced_keys=frozenset({"idle_hours", "pressure_idle_hours", "pressure_free_gb",
                           "unregistered_grace_hours", "snapshot_max_mb",
                           "repo_free_floor_gb"}),
    secret_keys=frozenset(),
    home_subkeys={},
    union_arrays=(),
    one_way=frozenset(),
    deep=False,
    strict_inbound=True,
    locate=worktrees_path,
    hookable=False,
)


def all_domains() -> dict:
    return {"claude": _claude(), "desk": DESK, "mods": MODS, "memory": MEMORY,
            "companions": COMPANIONS, "aitherzero": AITHERZERO, "darkmatter": DARKMATTER,
            "worktrees": WORKTREES}


def get_domain(name: str | None) -> Domain:
    """Look a domain up by name. An unknown name RAISES -- it never falls back to
    the default, because "synced the wrong file and said ok" is the worst outcome
    this package can produce."""
    domains = all_domains()
    key = (name or "claude").strip().lower()
    if key not in domains:
        raise KeyError(f"unknown domain {name!r}; known: {', '.join(sorted(domains))}")
    return domains[key]
