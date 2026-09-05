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
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .store import CouldNotRunError
from .trust import verify

#: Namespace inside the remote object, so this never stomps another app's prefs.
NAMESPACE = "awsettings"


def require_seal() -> bool:
    """Refuse an UNSEALED profile. Off by default so the brick is adoptable with
    no keys at all; set it once you have signed, so that deleting the seal cannot
    silently downgrade a machine that was verifying."""
    return (os.getenv("AWSETTINGS_REQUIRE_SEAL") or "").strip().lower() in (
        "1", "true", "yes", "on")

DEFAULT_FILE_PROFILE = Path.home() / ".awsettings" / "profile.json"


class Backend:
    """A profile store. Two methods, both of which must raise on failure."""

    def get(self) -> dict[str, Any]:
        raise NotImplementedError

    def put(self, snapshot: dict[str, Any]) -> None:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError


class FileBackend(Backend):
    def __init__(self, path: Path):
        self.path = path

    def get(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CouldNotRunError(f"profile {self.path} is unreadable: {exc}") from exc
        if not isinstance(data, dict):
            raise CouldNotRunError(f"profile {self.path} is not an object")
        ns = data.get(NAMESPACE, {})
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
        existing[NAMESPACE] = snapshot
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
        os.replace(tmp, self.path)

    def describe(self) -> str:
        return f"file:{self.path}"


class HttpBackend(Backend):
    def __init__(self, url: str, token: str | None, timeout: float = 15.0):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def get(self) -> dict[str, Any]:
        import httpx
        try:
            r = httpx.get(self.url, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:                                   # noqa: BLE001
            raise CouldNotRunError(f"GET {self.url}: {exc}") from exc
        if not isinstance(data, dict):
            raise CouldNotRunError(f"GET {self.url} did not return an object")
        ns = data.get(NAMESPACE, data)
        if not isinstance(ns, dict):
            return {}
        # Same trust port as the file backend. A profile fetched over the network
        # is the case the seal exists for, so this must not be the lenient path.
        return verify(ns, require_seal=require_seal())

    def put(self, snapshot: dict[str, Any]) -> None:
        import httpx
        try:
            r = httpx.put(self.url, headers=self._headers(),
                          json={NAMESPACE: snapshot}, timeout=self.timeout)
            r.raise_for_status()
        except Exception as exc:                                   # noqa: BLE001
            raise CouldNotRunError(f"PUT {self.url}: {exc}") from exc

    def describe(self) -> str:
        return f"http:{self.url}" + ("" if self.token else " (no token)")


def resolve(url: str | None = None, path: str | None = None) -> Backend:
    """Pick a backend. Explicit argument, then environment, then the local file.

    The token is read from the environment ONLY. A credential passed on a command
    line lands in shell history and in the process list, where anything on the
    box can read it.
    """
    url = url or os.getenv("AWSETTINGS_URL")
    if url:
        return HttpBackend(url, os.getenv("AWSETTINGS_TOKEN"))
    p = Path(path or os.getenv("AWSETTINGS_PROFILE") or DEFAULT_FILE_PROFILE)
    return FileBackend(p)
