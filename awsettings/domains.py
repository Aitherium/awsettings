"""What is being synced. One merge engine, more than one settings file.

This package began as a sync for ONE file: a coding agent's personal settings. The
three rules it enforces (credentials stay home, arrays union, a deny is one-way) are
not about that file, though -- they are about any config edited from more than one
machine. A **domain** is the small table that tells the engine how to apply them to
a particular file: where it lives, which keys travel, which stay home, which arrays
union.

Three domains ship:

* ``claude`` -- the coding agent's ``settings.local.json``. The original behaviour,
  bit for bit; it is the default so nothing that already calls this package moves.
* ``desk``   -- a desktop avatar's ``cast.json``: who gets a body, which voice, how
  fast, **how loud**, where they stand. It is a plain JSON file the desktop app
  watches, so a pull lands live with no restart.

* ``mods``   -- ``~/.aither/mods.json``: which harness, backend and model a coding
  agent's `aw` subagent runs on when the prompt does not say. The Claude Code mod
  reads it on every spawn, so a pull changes the next spawn with no restart.

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
    #: Resolves the local file. ``root`` is a project dir, or None for user-level.
    locate: Callable = local_settings_path
    #: Whether the agent-harness hooks make sense for this file.
    hookable: bool = False


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
        home_subkeys=dict(core.SECRET_SUBKEYS),
        union_arrays=core.UNION_ARRAYS,
        one_way=frozenset({"deny", "ask"}),
        deep=False,
        locate=local_settings_path,
        hookable=True,
    )


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
    synced_keys=frozenset({"version", "aw"}),
    secret_keys=frozenset(),
    # Where the harness daemon listens is one machine's topology, exactly like a
    # voice endpoint: never sent, never accepted on arrival.
    home_subkeys={"aw": frozenset({"daemon"})},
    union_arrays=(),
    one_way=frozenset(),
    deep=True,
    strict_inbound=True,
    locate=mods_path,
    hookable=False,
)


def all_domains() -> dict:
    return {"claude": _claude(), "desk": DESK, "mods": MODS}


def get_domain(name: str | None) -> Domain:
    """Look a domain up by name. An unknown name RAISES -- it never falls back to
    the default, because "synced the wrong file and said ok" is the worst outcome
    this package can produce."""
    domains = all_domains()
    key = (name or "claude").strip().lower()
    if key not in domains:
        raise KeyError(f"unknown domain {name!r}; known: {', '.join(sorted(domains))}")
    return domains[key]
