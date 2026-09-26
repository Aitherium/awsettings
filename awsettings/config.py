"""Settings for awsettings itself: environment first, then ~/.awsettings/config.json.

The file exists so sign-in can configure sync. `adk enroll` writes it once; before
it, every machine needed five environment variables set by hand, which is the step
nobody does. An environment variable still wins, so nothing that works today changes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

#: config.json key -> the environment variable it stands in for.
KEYS = {
    "url": "AWSETTINGS_URL",
    "token_file": "AWSETTINGS_TOKEN_FILE",
    "keys_url": "AWSETTINGS_KEYS_URL",
    "sign": "AWSETTINGS_SIGN",
    "require_seal": "AWSETTINGS_REQUIRE_SEAL",
    "public_key": "AWSETTINGS_PUBLIC_KEY",
}


def home() -> Path:
    return Path(os.getenv("AWSETTINGS_HOME") or Path.home() / ".awsettings")


def config_path() -> Path:
    return home() / "config.json"


def load() -> dict[str, Any]:
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def get(env_name: str) -> str:
    """The value for `env_name`: the environment, else the config file, else ""."""
    value = (os.getenv(env_name) or "").strip()
    if value:
        return value
    for key, var in KEYS.items():
        if var == env_name:
            raw = load().get(key)
            if isinstance(raw, bool):
                return "1" if raw else ""
            return str(raw).strip() if raw is not None else ""
    return ""


def flag(env_name: str) -> bool:
    return get(env_name).lower() in ("1", "true", "yes", "on")


def save(values: dict[str, Any]) -> Path:
    """Merge `values` into config.json (unknown keys refused, None removes a key)."""
    unknown = sorted(set(values) - set(KEYS))
    if unknown:
        raise ValueError(f"unknown awsettings config key(s): {', '.join(unknown)}")
    data = load()
    for key, value in values.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
