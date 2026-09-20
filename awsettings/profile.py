"""The remote half — a profile endpoint, and the option of no endpoint at all.

Two backends, and the local one is not a toy:

* **file** — a directory you already sync (a git repo, a drive folder, a USB
  stick). No account, no server, no network. This is the default, because the
  brick has to be adoptable by a stranger with two laptops and nothing else; a
  tool that requires an account to try is a tool most people never try.
* **http** — a profile endpoint holding a namespaced settings blob. Whatever
  serves it, the contract is the same: GET returns the object, PUT merges it.

**A transport failure is never "no settings".** Both backends raise rather than
returning `{}` on error. Reading a failed fetch as an empty profile would merge
nothing and report success — the sync equivalent of a green run over a dead
store, and the single easiest way for this to quietly stop working.

**A 200 is not "stored".** Two server shapes exist in the wild and they are not
interchangeable:

    bare          GET -> {"<namespace>": {...}}            PUT {"<namespace>": {...}}
    preferences   GET -> {"preferences": {"<ns>": {...}}}  PUT {"preferences": {...}}

This client once spoke only the first. Pointed at a server of the second kind, a
push sent a body the server did not look inside, the server merged NOTHING and
answered 200, and the CLI printed "pushed". So the shape is detected rather than
assumed, and after a PUT the server's echo is compared with what was sent: a key
the server dropped is reported by path, and an echo with nothing under our
namespace is a failure, not a success.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .store import CouldNotRunError
from .trust import verify

#: Namespace inside the remote object, so this never stomps another app's prefs.
#: This is the ORIGINAL domain's namespace; every other domain carries its own.
NAMESPACE = "awsettings"

ENVELOPES = ("auto", "bare", "preferences")


class ProfileRejectedError(Exception):
    """The server answered, and did not keep what it was sent. Callers exit 1: this
    is a rule refusing the write, not an unreachable profile."""

    def __init__(self, message: str, dropped: list[str] | None = None):
        super().__init__(message)
        self.dropped = list(dropped or [])


def require_seal() -> bool:
    """Refuse an UNSEALED profile. Off by default so the brick is adoptable with
    no keys at all; set it once you have signed, so that deleting the seal cannot
    silently downgrade a machine that was verifying."""
    return (os.getenv("AWSETTINGS_REQUIRE_SEAL") or "").strip().lower() in (
        "1", "true", "yes", "on")


DEFAULT_FILE_PROFILE = Path.home() / ".awsettings" / "profile.json"


class Backend:
    """A profile store. Two methods, both of which must raise on failure."""

    namespace = NAMESPACE

    def get(self) -> dict[str, Any]:
        raise NotImplementedError

    def put(self, snapshot: dict[str, Any]) -> None:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError


class FileBackend(Backend):
    def __init__(self, path: Path, namespace: str = NAMESPACE):
        self.path = path
        self.namespace = namespace

    def get(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CouldNotRunError(f"profile {self.path} is unreadable: {exc}") from exc
        if not isinstance(data, dict):
            raise CouldNotRunError(f"profile {self.path} is not an object")
        ns = data.get(self.namespace, {})
        if not isinstance(ns, dict):
            return {}
        # Every read goes through the trust port. When the profile carries no seal
        # this returns it unchanged; when it carries one, a bad or uncheckable seal
        # RAISES rather than degrading to "apply it anyway".
        return verify(ns, require_seal=require_seal())

    def put(self, snapshot: dict[str, Any]) -> None:
        try:
            existing = json.loads(self.path.read_text(encoding="utf-8") or "{}") \
                if self.path.is_file() else {}
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            existing = {}
        if not isinstance(existing, dict):
            existing = {}
        # Only OUR namespace is replaced: a second domain's blob in the same file
        # is somebody else's settings and survives this write untouched.
        existing[self.namespace] = snapshot
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
        os.replace(tmp, self.path)

    def describe(self) -> str:
        return f"file:{self.path} [{self.namespace}]"


def missing_paths(sent: Any, echoed: Any, prefix: str = "") -> list[str]:
    """Every key path present in ``sent`` and absent from ``echoed``.

    Keys only, never values: a server may legitimately normalise a value, but a key
    that went in and did not come back was DROPPED, and the usual reason is a
    server-side filter matching on the key's name.
    """
    if not isinstance(sent, dict):
        return []
    if not isinstance(echoed, dict):
        return [prefix or "<root>"]
    out: list[str] = []
    for k, v in sent.items():
        path = f"{prefix}.{k}" if prefix else str(k)
        if k not in echoed:
            out.append(path)
        else:
            out.extend(missing_paths(v, echoed[k], path))
    return out


class HttpBackend(Backend):
    def __init__(self, url: str, token: str | None, timeout: float = 15.0,
                 namespace: str = NAMESPACE, envelope: str = "auto"):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.namespace = namespace
        if envelope not in ENVELOPES:
            raise CouldNotRunError(
                f"unknown envelope {envelope!r}; expected one of {', '.join(ENVELOPES)}")
        self.envelope = envelope
        #: What the server was SEEN to speak. None until a GET has looked.
        self._shape: str | None = None if envelope == "auto" else envelope

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    # -- transport, separated so the shape logic is testable without a network --
    def _request(self, method: str, body: dict[str, Any] | None = None) -> Any:
        import httpx
        try:
            r = httpx.request(method, self.url, headers=self._headers(), json=body,
                              timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:                                   # noqa: BLE001
            raise CouldNotRunError(f"{method} {self.url}: {exc}") from exc

    def _fetch(self) -> dict[str, Any]:
        data = self._request("GET")
        if not isinstance(data, dict):
            raise CouldNotRunError(f"GET {self.url} did not return an object")
        if self.envelope == "auto":
            wrapped = isinstance(data.get("preferences"), dict) and self.namespace not in data
            self._shape = "preferences" if wrapped else "bare"
        return data

    def get(self) -> dict[str, Any]:
        data = self._fetch()
        if self._shape == "preferences":
            prefs = data.get("preferences")
            # Absent namespace = nothing stored for this domain yet. NEVER the
            # whole object: that is every other app's preferences, and merging
            # them into a settings file is the bug this shape check exists for.
            ns = prefs.get(self.namespace, {}) if isinstance(prefs, dict) else {}
        else:
            ns = data.get(self.namespace, data)
        if not isinstance(ns, dict):
            return {}
        # Same trust port as the file backend. A profile fetched over the network
        # is the case the seal exists for, so this must not be the lenient path.
        return verify(ns, require_seal=require_seal())

    def put(self, snapshot: dict[str, Any]) -> None:
        if self._shape is None:
            # One extra GET, paid once per process, to learn what the server
            # speaks. Guessing is what produced a push that stored nothing.
            self._fetch()
        if self._shape == "preferences":
            body: dict[str, Any] = {"preferences": {self.namespace: snapshot}}
        else:
            body = {self.namespace: snapshot}
        reply = self._request("PUT", body)
        self._confirm(snapshot, reply)

    def _confirm(self, snapshot: dict[str, Any], reply: Any) -> None:
        """Did the server keep it? Only judged when the reply carries an echo; a
        server that answers `{}` or `{"ok": true}` gives nothing to compare."""
        if not isinstance(reply, dict):
            return
        if self._shape == "preferences":
            prefs = reply.get("preferences")
            if not isinstance(prefs, dict):
                return
            echoed = prefs.get(self.namespace)
        else:
            if self.namespace not in reply:
                return
            echoed = reply.get(self.namespace)
        if snapshot and not isinstance(echoed, dict):
            raise ProfileRejectedError(
                f"PUT {self.url} answered OK and stored nothing under "
                f"{self.namespace!r} -- the server did not read the body it was sent",
                [self.namespace])
        dropped = missing_paths(snapshot, echoed)
        if dropped:
            raise ProfileRejectedError(
                f"PUT {self.url} stored the profile but DROPPED {len(dropped)} key(s). "
                f"A server-side filter usually matches on the key's NAME; rename the "
                f"key or keep it local.", dropped)

    def describe(self) -> str:
        shape = self._shape or "shape not yet seen"
        return (f"http:{self.url} [{self.namespace}; {shape}]"
                + ("" if self.token else " (no token)"))


def resolve_token() -> str | None:
    """The bearer, from the environment or from a FILE named by the environment.

    Never a command-line flag: a credential on a command line lands in shell
    history and in the process list, where anything on the box can read it. A
    *path* is not a credential, so `AWSETTINGS_TOKEN_FILE` is safe to export, and it
    lets a token that some other tool already rotates be used without copying it.
    """
    token = (os.getenv("AWSETTINGS_TOKEN") or "").strip()
    if token:
        return token
    token_file = (os.getenv("AWSETTINGS_TOKEN_FILE") or "").strip()
    if not token_file:
        return None
    path = Path(token_file).expanduser()
    try:
        token = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        # Named, and fatal: silently continuing with NO token turns "my token file
        # moved" into an anonymous request and a confusing 401 from somewhere else.
        raise CouldNotRunError(f"AWSETTINGS_TOKEN_FILE {path} is unreadable: {exc}") from exc
    return token or None


def resolve(url: str | None = None, path: str | None = None,
            namespace: str = NAMESPACE) -> Backend:
    """Pick a backend. Explicit argument, then environment, then the local file."""
    url = url or os.getenv("AWSETTINGS_URL")
    if url:
        envelope = (os.getenv("AWSETTINGS_ENVELOPE") or "auto").strip().lower()
        return HttpBackend(url, resolve_token(), namespace=namespace, envelope=envelope)
    p = Path(path or os.getenv("AWSETTINGS_PROFILE") or DEFAULT_FILE_PROFILE)
    return FileBackend(p, namespace=namespace)
