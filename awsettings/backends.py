"""Which model backends can this machine launch a coding session on, and how.

    from awsettings.backends import discover
    for b in discover():
        print(b.id, b.launcher, b.model)

WHY THIS EXISTS
---------------------------------------------------------------------------
A coding-agent backend -- which model actually answers -- is decided ONCE, at
process launch, by environment variables the harness reads on startup. Nothing
can repoint a session that is already running. That single fact has a
consequence people keep rediscovering the hard way: **the launcher is the only
place a backend can be chosen**, so every surface that starts a session needs to
know the roster, and every surface was deriving it for itself.

Measured in this repo on 2026-09-10: the session-restore engine derived the
roster in PowerShell, from a regex over the launcher shims. The regex demanded
whitespace immediately after `claude-backend.ps1`, every shim quotes that path,
and so the roster silently collapsed to "default backend only" -- a backend
picker that could not offer a backend, with nothing raising. The next surface to
want this list (a desktop overlay, a shell, an SDK) would have written a fourth
copy of the same regex and earned its own version of that bug.

So: one resolver, read by all of them. This module DISCOVERS and never applies.

THE RULE IT MUST NOT BREAK
---------------------------------------------------------------------------
Backend overrides are session-scoped by design. They belong in the environment
of the process being launched and nowhere else -- never a persistent user or
machine variable, never a settings file, never a saved default. This module
therefore returns *descriptions* of how to launch, and writes nothing. The
profile DEFINITIONS are shareable config; an ACTIVE override is not, and the two
must not be confused because `awsettings` exists to sync the former.

CONFIGURED IS NOT WORKING
---------------------------------------------------------------------------
`discover()` answers "could this machine launch it". That is not the same
question as "will it answer", and the gap between them is where the real pain
is: a backend can be configured, its launcher on PATH, its model name valid, and
still be dead because the key is absent, the balance is empty, or the endpoint
has never heard of that model. Launching into that costs the user a whole
session -- the harness comes up, the first turn fails, and the failure looks like
the harness rather than the backend.

`probe()` is therefore a separate, deliberate step: one minimal request, and a
CLASSIFIED verdict rather than a boolean, because the fix differs completely.
No-credit needs a payment; a bad key needs a rotation; a wrong model name needs
an edit. "It didn't work" tells the user none of that.

The verdicts are in `ProbeVerdict`. `UNKNOWN` exists and is never treated as a
pass: a probe that could not reach a conclusion is dead, not healthy.

USABLE ALONE
---------------------------------------------------------------------------
On a machine with no launcher shims and no profile file, `discover()` returns
exactly one entry: the harness default. That is the honest answer, not an empty
list, and it means a caller can render a picker unconditionally.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

#: The harness default: no variables at all, whatever the user is signed in as.
#: Present on every machine, which is why it is a constant and not discovered.
DEFAULT_LAUNCHER = "claude"

#: Shims are named c<x>s: cds (deepseek), cks (kimi), cas (anthropic). The `cbs`
#: shim is deliberately excluded by the parser below -- it forwards its own
#: subcommand rather than naming a profile, so it is a switcher entry point, not
#: a backend.
_SHIM_GLOBS = ("c*s.cmd", "c*s")

#: `"?` is load-bearing: every generated shim quotes the script path, and a
#: pattern demanding whitespace straight after `.ps1` matches nothing. That exact
#: omission is the bug this module was extracted to stop repeating.
_SHIM_USE = re.compile(r'claude-backend\.ps1"?\s+use\s+([A-Za-z0-9._-]+)')

#: Pull the switcher path back out of the shim, so the profile file can be found
#: as its sibling without assuming a repo checkout exists anywhere.
_SHIM_SCRIPT = re.compile(r'-File\s+"?([^"\r\n]*claude-backend\.ps1)"?')


class CouldNotJudgeError(Exception):
    """A source existed but could not be read. Never silently treated as empty."""


@dataclass
class Backend:
    """One launchable backend."""

    id: str
    launcher: str
    model: str
    base_url: str = ""
    source: str = ""
    launchable: bool = True
    #: Set when the profile exists but nothing on PATH applies it. The caller
    #: should show it greyed out with `hint`, not hide it -- a backend that is
    #: configured but unreachable is a fact worth seeing.
    hint: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _bin_dir(override: str | os.PathLike | None = None) -> Path:
    if override:
        return Path(override)
    env = os.environ.get("AWSETTINGS_LAUNCHER_BIN")
    if env:
        return Path(env)
    return Path.home() / ".aither" / "bin"


def _profile_candidates(shim_script: Path | None) -> list[Path]:
    """Where profiles.json might be, most authoritative first.

    The shim itself is the best source: it carries the absolute path of the
    switcher it runs, and the profile file is that script's sibling. Everything
    else is a fallback for a box where the shims are absent.
    """
    out: list[Path] = []
    env = os.environ.get("AWSETTINGS_BACKEND_PROFILES")
    if env:
        out.append(Path(env))
    if shim_script is not None:
        out.append(shim_script.parent / "profiles.json")
    out.append(Path.home() / ".aither" / "claude-backend" / "profiles.json")
    return out


def _load_profiles(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CouldNotJudgeError(f"cannot read {path}: {exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CouldNotJudgeError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise CouldNotJudgeError(f"{path} is not an object")
    # Keys starting with `_` are documentation blocks, not profiles.
    return {k: v for k, v in doc.items() if not k.startswith("_")}


def _shims(bin_dir: Path) -> list[tuple[str, str, Path]]:
    """[(launcher command, profile name, switcher script path)] found in bin_dir."""
    if not bin_dir.is_dir():
        return []
    seen: set[str] = set()
    found: list[tuple[str, str, Path]] = []
    for pattern in _SHIM_GLOBS:
        for shim in sorted(bin_dir.glob(pattern)):
            if not shim.is_file() or shim.name in seen:
                continue
            seen.add(shim.name)
            try:
                body = shim.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            use = _SHIM_USE.search(body)
            if not use:
                # A switcher entry point (`cbs`) rather than a backend. Skipping
                # it is correct: it has no profile of its own to offer.
                continue
            script = _SHIM_SCRIPT.search(body)
            script_path = Path(script.group(1)) if script else shim
            found.append((shim.stem, use.group(1), script_path))
    return found


def _model_of(profile: dict) -> str:
    variables = (profile or {}).get("vars") or {}
    return variables.get("ANTHROPIC_MODEL") or ""


def _base_url_of(profile: dict) -> str:
    variables = (profile or {}).get("vars") or {}
    return variables.get("ANTHROPIC_BASE_URL") or ""


def discover(
    bin_dir: str | os.PathLike | None = None,
    profiles: dict | None = None,
    have_command=None,
) -> list[Backend]:
    """Every backend this machine can launch, default first.

    ``profiles`` and ``have_command`` are injectable so the self-test drives the
    real code path instead of whatever this particular box happens to hold. A
    discovery function that can only be exercised on one machine is a function
    nobody has watched fail.
    """
    if have_command is None:

        def have_command(name: str) -> bool:
            return shutil.which(name) is not None

    out = [
        Backend(
            id="default",
            launcher=DEFAULT_LAUNCHER,
            model="",
            source="harness default",
            launchable=have_command(DEFAULT_LAUNCHER),
            hint=(
                ""
                if have_command(DEFAULT_LAUNCHER)
                else f"'{DEFAULT_LAUNCHER}' is not on PATH"
            ),
            notes=["whatever account this machine is signed in as; sets no variables"],
        )
    ]

    shims = _shims(_bin_dir(bin_dir))
    script_hint = shims[0][2] if shims else None

    loaded = profiles
    profile_source = "injected"
    if loaded is None:
        loaded = {}
        errors: list[str] = []
        for candidate in _profile_candidates(script_hint):
            if not candidate.exists():
                continue
            try:
                loaded = _load_profiles(candidate)
                profile_source = str(candidate)
                break
            except CouldNotJudgeError as exc:
                # A present-but-broken profile file is NOT the same as an absent
                # one, and must not read as "this box has one backend".
                errors.append(str(exc))
        if not loaded and errors:
            raise CouldNotJudgeError("; ".join(errors))

    # Strip documentation keys HERE, not only on the file path. The `_`-prefixed
    # blocks in profiles.json hold prose and lists, and an injected dict skips
    # the loader entirely -- so filtering there left the self-test feeding a list
    # into a `.get()` and the real bug would have been an OFFERED backend named
    # `_README`. Filter where the data is consumed, not where it arrives.
    loaded = {
        name: body
        for name, body in loaded.items()
        if not name.startswith("_") and isinstance(body, dict)
    }

    claimed: set[str] = set()
    for launcher, profile_name, _script in shims:
        profile = loaded.get(profile_name)
        if profile is None:
            # A shim naming a profile that no longer exists dies at launch, after
            # the terminal is already open. Do not offer it.
            continue
        claimed.add(profile_name)
        model = _model_of(profile)
        if not model:
            # A profile with no model is the default backend spelled out
            # explicitly; it is the same thing as the entry already at index 0.
            continue
        runnable = have_command(launcher)
        out.append(
            Backend(
                id=profile_name,
                launcher=launcher,
                model=model,
                base_url=_base_url_of(profile),
                source=profile_source,
                launchable=runnable,
                hint="" if runnable else f"'{launcher}' is not on PATH",
            )
        )

    # Profiles with no shim: real config the caller should see, with the exact
    # command that would apply them, rather than a silently shorter list.
    for profile_name, profile in sorted(loaded.items()):
        if profile_name in claimed:
            continue
        model = _model_of(profile)
        if not model:
            continue
        out.append(
            Backend(
                id=profile_name,
                launcher="",
                model=model,
                base_url=_base_url_of(profile),
                source=profile_source,
                launchable=False,
                hint=f"no launcher shim; run the switcher directly: use {profile_name}",
            )
        )

    # Two spellings of one backend read as two choices in a picker. Keep the
    # first, which is the harness default when the model matches it.
    deduped: list[Backend] = []
    seen_models: set[tuple[str, str]] = set()
    for backend in out:
        key = (backend.model, backend.base_url)
        if key in seen_models:
            continue
        seen_models.add(key)
        deduped.append(backend)
    return deduped


def as_json(backends: list[Backend] | None = None) -> str:
    if backends is None:
        backends = discover()
    return json.dumps([b.as_dict() for b in backends], indent=2)


def self_test() -> int:
    """Prove the resolver can still fail. Returns 0 pass, 1 fail."""
    fails: list[str] = []

    quoted_shim = (
        '@echo off\r\n'
        'pwsh -NoProfile -ExecutionPolicy Bypass -File '
        '"C:\\repo\\tools\\claude-backend\\claude-backend.ps1" use deepseek %*\r\n'
    )
    if not _SHIM_USE.search(quoted_shim):
        fails.append("the shim parser cannot read a QUOTED script path (the original bug)")
    if not _SHIM_SCRIPT.search(quoted_shim):
        fails.append("the switcher path cannot be recovered from a shim")

    forwarding_shim = (
        '@echo off\r\npwsh -File "C:\\repo\\tools\\claude-backend\\claude-backend.ps1" %*\r\n'
    )
    if _SHIM_USE.search(forwarding_shim):
        fails.append("a forwarding shim (cbs) was mistaken for a backend")

    profiles = {
        "_README": ["documentation, not a profile"],
        "anthropic": {"vars": None},
        "deepseek": {
            "vars": {
                "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
                "ANTHROPIC_MODEL": "deepseek-v4-flash[1m]",
            }
        },
        "orphan": {"vars": {"ANTHROPIC_MODEL": "no-shim-model"}},
    }

    everything = discover(bin_dir="/does/not/exist", profiles=profiles, have_command=lambda n: True)
    ids = [b.id for b in everything]
    if ids[0] != "default":
        fails.append(f"the harness default is not first: {ids}")
    if "_README" in ids:
        fails.append("a documentation key was offered as a backend")
    orphan = [b for b in everything if b.id == "orphan"]
    if not orphan:
        fails.append("a profile with no shim was hidden instead of shown as unlaunchable")
    elif orphan[0].launchable or not orphan[0].hint:
        fails.append("an unlaunchable profile was not marked with a hint")

    bare = discover(bin_dir="/does/not/exist", profiles={}, have_command=lambda n: True)
    if [b.id for b in bare] != ["default"]:
        fails.append(f"a machine with no profiles should offer exactly the default: {[b.id for b in bare]}")

    missing = discover(bin_dir="/does/not/exist", profiles={}, have_command=lambda n: False)
    if missing[0].launchable or not missing[0].hint:
        fails.append("an absent harness was still reported launchable")

    if fails:
        print("backends self-test FAILED")
        for f in fails:
            print(f"  FAIL {f}")
        return 1
    print(f"backends self-test OK  ({len(everything)} discovered from the injected fixture)")
    return 0


# ---------------------------------------------------------------------------
# Is it actually working?
# ---------------------------------------------------------------------------

#: A probe must be cheap enough that a launcher can afford it every time. One
#: token in, one token out, against the smallest legal request the
#: Anthropic-compatible shape allows.
_PROBE_BODY = {"max_tokens": 1, "messages": [{"role": "user", "content": "."}]}
_PROBE_TIMEOUT = 12.0

#: Re-probing on every launch of every tab would add seconds to a nine-tab
#: restore for an answer that changes on the timescale of a billing cycle. The
#: cache is per-user, short, and keyed so a rotated key invalidates it.
_CACHE_PATH = Path.home() / ".awsettings" / "backend-probe-cache.json"
_CACHE_SECONDS = 900.0


class ProbeVerdict(str, Enum):
    """Why a backend is or is not usable. The fix differs for every value."""

    OK = "ok"
    #: The key is missing entirely -- nothing to send.
    NO_CREDENTIAL = "no-credential"
    #: A key was sent and rejected. Rotate it.
    BAD_CREDENTIAL = "bad-credential"
    #: Authenticated and broke. Add funds or raise the cap.
    NO_CREDIT = "no-credit"
    #: The endpoint has never heard of this model name. Edit the profile.
    UNKNOWN_MODEL = "unknown-model"
    #: Working, but throttled right now.
    RATE_LIMITED = "rate-limited"
    #: DNS, TLS, connection refused, timeout, or a 5xx.
    UNREACHABLE = "unreachable"
    #: Could not form an opinion. NEVER treated as a pass.
    UNKNOWN = "unknown"

    @property
    def usable(self) -> bool:
        """Would a session launched on this backend be able to answer a turn?

        RATE_LIMITED counts as usable on purpose: the credential and the model
        are both right, the limit is transient, and refusing to launch would
        strand a user who only had to wait. Everything else does not.
        """
        return self in (ProbeVerdict.OK, ProbeVerdict.RATE_LIMITED)


@dataclass
class Probe:
    backend_id: str
    verdict: ProbeVerdict
    detail: str = ""
    status: int = 0
    #: Milliseconds for the round trip; 0 when nothing was sent.
    latency_ms: int = 0
    cached: bool = False

    @property
    def usable(self) -> bool:
        return self.verdict.usable

    def as_dict(self) -> dict:
        out = asdict(self)
        out["verdict"] = self.verdict.value
        out["usable"] = self.usable
        return out


def classify(status: int, body: str) -> tuple[ProbeVerdict, str]:
    """Map an HTTP status plus body onto a verdict.

    Split out and pure so the self-test can drive every branch. Provider bodies
    are the only place some of these distinctions exist: DeepSeek answers an
    empty balance with 402 and the words "insufficient balance", while other
    providers use 400 with a message, so status alone cannot tell no-credit from
    a malformed request.
    """
    low = (body or "").lower()
    if status == 200:
        return ProbeVerdict.OK, ""
    if status in (401, 403):
        if "credit" in low or "balance" in low or "quota" in low:
            return ProbeVerdict.NO_CREDIT, "authenticated but out of credit"
        return ProbeVerdict.BAD_CREDENTIAL, "the endpoint rejected this key"
    if status == 402:
        return ProbeVerdict.NO_CREDIT, "payment required"
    if status == 429:
        if "credit" in low or "balance" in low or "quota" in low:
            return ProbeVerdict.NO_CREDIT, "quota exhausted"
        return ProbeVerdict.RATE_LIMITED, "throttled right now"
    if status == 404:
        return ProbeVerdict.UNKNOWN_MODEL, "the endpoint does not know this model name"
    if status == 400:
        if "model" in low and ("not found" in low or "does not exist" in low or "unknown" in low):
            return ProbeVerdict.UNKNOWN_MODEL, "the endpoint does not know this model name"
        if "credit" in low or "balance" in low or "quota" in low:
            return ProbeVerdict.NO_CREDIT, "authenticated but out of credit"
        return ProbeVerdict.UNKNOWN, f"HTTP 400: {(body or '')[:120]}"
    if 500 <= status <= 599:
        return ProbeVerdict.UNREACHABLE, f"the endpoint returned {status}"
    return ProbeVerdict.UNKNOWN, f"HTTP {status}: {(body or '')[:120]}"


def _cache_read(key: str) -> Probe | None:
    try:
        doc = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    row = (doc or {}).get(key)
    if not isinstance(row, dict):
        return None
    if time.time() - float(row.get("at", 0)) > _CACHE_SECONDS:
        return None
    try:
        verdict = ProbeVerdict(row["verdict"])
    except (KeyError, ValueError):
        return None
    return Probe(
        backend_id=row.get("backend_id", ""),
        verdict=verdict,
        detail=row.get("detail", ""),
        status=int(row.get("status", 0)),
        latency_ms=int(row.get("latency_ms", 0)),
        cached=True,
    )


def _cache_write(key: str, probe: Probe) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            doc = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                doc = {}
        except (OSError, json.JSONDecodeError):
            doc = {}
        row = probe.as_dict()
        row.pop("cached", None)
        row.pop("usable", None)
        row["at"] = time.time()
        doc[key] = row
        _CACHE_PATH.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    except OSError:
        # A cache that cannot be written must never fail a probe.
        pass


def _cache_key(backend: Backend, token: str) -> str:
    """Keyed on the token's FINGERPRINT, never its value.

    A rotated key must invalidate the cache, and the cache file sits in the
    user's home where a value would outlive the session that fetched it.
    """
    import hashlib

    digest = hashlib.sha256((token or "").encode("utf-8")).hexdigest()[:16]
    return f"{backend.id}|{backend.base_url}|{backend.model}|{digest}"


def probe(
    backend: Backend,
    token: str | None = None,
    use_cache: bool = True,
    transport=None,
) -> Probe:
    """One minimal request. Returns a classified verdict, never a bare boolean.

    ``transport`` is injectable -- ``transport(url, headers, body) -> (status,
    text)`` -- so the self-test exercises every branch of `classify` without a
    network or a key. The token is never logged, cached, or included in the
    return value.
    """
    if backend.launcher == DEFAULT_LAUNCHER and not backend.base_url:
        # The harness default authenticates through its own signed-in session,
        # which this module cannot see and must not guess at. Claiming OK would
        # be a fabricated pass; claiming failure would be worse.
        return Probe(
            backend.id,
            ProbeVerdict.UNKNOWN,
            "the harness default uses its own sign-in; check it with the harness itself",
        )
    if not backend.base_url or not backend.model:
        return Probe(backend.id, ProbeVerdict.UNKNOWN, "the profile names no endpoint or model")
    if not token:
        return Probe(
            backend.id,
            ProbeVerdict.NO_CREDENTIAL,
            "no key available for this profile in the environment or the vault",
        )

    if use_cache:
        hit = _cache_read(_cache_key(backend, token))
        if hit is not None:
            hit.backend_id = backend.id
            return hit

    url = backend.base_url.rstrip("/") + "/v1/messages"
    body = dict(_PROBE_BODY, model=backend.model)
    headers = {
        "x-api-key": token,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    started = time.monotonic()
    if transport is not None:
        try:
            status, text = transport(url, headers, body)
        except Exception as exc:  # noqa: BLE001 - an injected transport may raise anything
            status, text = 0, f"{type(exc).__name__}: {exc}"
    else:
        request = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=_PROBE_TIMEOUT) as response:
                status, text = response.status, response.read(400).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                text = exc.read(400).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                text = ""
        except Exception as exc:  # noqa: BLE001 - URLError, timeout, TLS, DNS
            status, text = 0, f"{type(exc).__name__}"
    latency = int((time.monotonic() - started) * 1000)

    if status == 0:
        result = Probe(
            backend.id, ProbeVerdict.UNREACHABLE, text or "no response", 0, latency
        )
    else:
        verdict, detail = classify(status, text)
        result = Probe(backend.id, verdict, detail, status, latency)

    if use_cache and result.verdict is not ProbeVerdict.UNKNOWN:
        _cache_write(_cache_key(backend, token), result)
    return result


def token_for(backend: Backend, profiles: dict | None = None, vault=None) -> str:
    """Best-effort key lookup for a profile. Returns "" rather than raising.

    Order: this process's environment, then the vault helper if one was passed.
    The VALUE is returned to the caller and never printed here; every call site
    in this package treats it as opaque.
    """
    if profiles is None:
        profiles = {}
    entry = profiles.get(backend.id) or {}
    name = entry.get("token_env")
    if not name:
        # A conventional guess, so a stranger with DEEPSEEK_API_KEY exported and
        # no profile metadata still gets a real answer.
        name = backend.id.split("-")[0].upper().replace(".", "_") + "_API_KEY"
    value = os.environ.get(name) or ""
    if not value and vault is not None:
        try:
            value = vault(name) or ""
        except Exception:  # noqa: BLE001 - a vault that is down is not a crash
            value = ""
    return value


def load_profiles_for_probe() -> dict:
    """The raw profile bodies, so a caller can read `token_env` off them.

    `discover()` deliberately returns a narrow view; a probe needs the metadata
    that names where the key lives. Returns {} rather than raising when there is
    no profile file at all -- a machine with only the harness default is a normal
    machine, not an error.
    """
    for candidate in _profile_candidates(None):
        if candidate.exists():
            try:
                return _load_profiles(candidate)
            except CouldNotJudgeError:
                return {}
    # No shim-derived path was tried above (that needs a shim); do that now.
    shims = _shims(_bin_dir())
    if shims:
        sibling = shims[0][2].parent / "profiles.json"
        if sibling.exists():
            try:
                return _load_profiles(sibling)
            except CouldNotJudgeError:
                return {}
    return {}


def vault_lookup(backend: Backend, profiles: dict | None = None) -> str:
    """A key for this profile: the environment, then an optional helper command.

    The helper is named by $AWSETTINGS_SECRET_CMD and invoked as
    `<cmd> <SECRET_NAME>`, with the value read from stdout. It is configuration
    rather than a hardcoded path ON PURPOSE: this package ships to strangers, so
    it must not carry the location of any particular organisation's vault tool,
    and a site that has one can point at it in one variable.

    The value is returned and never printed, logged, or cached here.
    """
    helper = os.environ.get("AWSETTINGS_SECRET_CMD")
    if not helper:
        return token_for(backend, profiles)

    def run(name: str) -> str:
        import shlex
        import subprocess

        argv = shlex.split(helper) + [name]
        try:
            done = subprocess.run(
                argv, capture_output=True, text=True, timeout=30, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if done.returncode != 0:
            return ""
        return (done.stdout or "").strip()

    return token_for(backend, profiles, vault=run)


def probe_self_test() -> int:
    """Prove the classifier and the probe can still fail."""
    fails: list[str] = []

    cases = [
        (200, "", ProbeVerdict.OK),
        (401, "invalid api key", ProbeVerdict.BAD_CREDENTIAL),
        (403, "Insufficient Balance", ProbeVerdict.NO_CREDIT),
        (402, "payment required", ProbeVerdict.NO_CREDIT),
        (429, "rate limit exceeded", ProbeVerdict.RATE_LIMITED),
        (429, "monthly quota exhausted", ProbeVerdict.NO_CREDIT),
        (404, "Not found the model kimi-k3[1m]", ProbeVerdict.UNKNOWN_MODEL),
        (400, "model does not exist", ProbeVerdict.UNKNOWN_MODEL),
        (400, "insufficient balance", ProbeVerdict.NO_CREDIT),
        (503, "upstream unavailable", ProbeVerdict.UNREACHABLE),
        (418, "teapot", ProbeVerdict.UNKNOWN),
    ]
    for status, body, want in cases:
        got, _ = classify(status, body)
        if got is not want:
            fails.append(f"classify({status}, {body!r}) = {got.value}, expected {want.value}")

    if ProbeVerdict.UNKNOWN.usable:
        fails.append("UNKNOWN counted as usable - a probe with no verdict must never pass")
    if not ProbeVerdict.RATE_LIMITED.usable:
        fails.append("RATE_LIMITED counted as unusable - the credential and model are both fine")
    if ProbeVerdict.NO_CREDIT.usable or ProbeVerdict.BAD_CREDENTIAL.usable:
        fails.append("a broken credential or empty balance counted as usable")

    live = Backend(id="x", launcher="cx", model="m", base_url="https://example.invalid")
    if probe(live, token="", use_cache=False).verdict is not ProbeVerdict.NO_CREDENTIAL:
        fails.append("an absent key was not reported as NO_CREDENTIAL")

    def dead(url, headers, body):
        raise TimeoutError("timed out")

    if probe(live, token="k", use_cache=False, transport=dead).verdict is not ProbeVerdict.UNREACHABLE:
        fails.append("a transport that raises was not reported as UNREACHABLE")

    def broke(url, headers, body):
        return 402, "Insufficient Balance"

    result = probe(live, token="k", use_cache=False, transport=broke)
    if result.verdict is not ProbeVerdict.NO_CREDIT or result.usable:
        fails.append("an out-of-credit backend was reported usable")

    def fine(url, headers, body):
        if headers.get("x-api-key") != "k":
            return 401, "no key sent"
        return 200, '{"id":"x"}'

    if not probe(live, token="k", use_cache=False, transport=fine).usable:
        fails.append("a working backend was not reported usable")

    default = Backend(id="default", launcher=DEFAULT_LAUNCHER, model="")
    if probe(default, token="k", use_cache=False).verdict is not ProbeVerdict.UNKNOWN:
        fails.append("the harness default was given a fabricated verdict")

    if fails:
        print("probe self-test FAILED")
        for f in fails:
            print(f"  FAIL {f}")
        return 1
    print(f"probe self-test OK  ({len(cases)} classifier cases + 5 probe paths)")
    return 0
