"""The trusted-key list: the user's enrolled devices, from the device registry.

`awsettings trust refresh` GETs AWSETTINGS_KEYS_URL with the same bearer as the
settings store and expects {"keys": [{"device_id": ..., "seal_pubkey": <hex>}]}.
The list is cached in ~/.awsettings/trusted-keys.json so a laptop offline still
verifies against the devices it last saw. A revoked device drops off at the next
refresh; `pull` refreshes first when the cache is older than an hour.
"""

from __future__ import annotations

import json
import time
from typing import Any

from . import config
from .store import CouldNotRunError
from .trust import trusted_keys_path

STALE_SECONDS = 3600


def _valid(entry: Any) -> bool:
    key = entry.get("seal_pubkey") if isinstance(entry, dict) else None
    if not isinstance(key, str):
        return False
    try:
        return len(bytes.fromhex(key.strip())) == 32
    except ValueError:
        return False


def refresh(keys_url: str | None = None, token: str | None = None) -> list[dict[str, Any]]:
    """Fetch the device list and cache it. Raises CouldNotRunError, never returns []
    on a failure: an empty list would read as "every device was revoked"."""
    url = keys_url or config.get("AWSETTINGS_KEYS_URL")
    if not url:
        raise CouldNotRunError("no device registry: set AWSETTINGS_KEYS_URL or run "
                               "`awsettings enroll`")
    if token is None:
        from .profile import resolve_token
        token = resolve_token()
    import httpx
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = httpx.get(url, headers=headers, timeout=15.0)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:                                   # noqa: BLE001
        raise CouldNotRunError(f"GET {url}: {exc}") from exc
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list):
        raise CouldNotRunError(f"GET {url} did not return {{\"keys\": [...]}}")
    good = [k for k in keys if _valid(k)]
    write_cache(good)
    return good


def write_cache(keys: list[dict[str, Any]]) -> None:
    path = trusted_keys_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"fetched_at": time.time(), "keys": keys}, indent=2) + "\n",
                    encoding="utf-8")


def stale() -> bool:
    try:
        data = json.loads(trusted_keys_path().read_text(encoding="utf-8"))
        return time.time() - float(data.get("fetched_at") or 0) > STALE_SECONDS
    except (OSError, ValueError, TypeError):
        return True
