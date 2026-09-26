"""A pull trusts the user's ENROLLED DEVICES: any of them may sign, nothing else may.

Owner decision 2026-09-25: every device gets its own signing key at `adk enroll`;
the device registry lists the non-revoked ones; a seal names its signer and a pull
accepts it only when that signer is on the list. Revoking a device in the workspace
removes it at the next refresh.
"""

from __future__ import annotations

import json
import types

import pytest
from awsettings import cli, config, devices
from awsettings.store import CouldNotRunError
from awsettings.trust import SIGNER_KEY, UntrustedProfileError, seal, trusted_keys, verify

awseal = pytest.importorskip("awseal")

PROFILE = {"permissions": {"allow": ["Bash(git status:*)"]}}


def _device(tmp_path, name):
    key = tmp_path / f"{name}.key"
    awseal.keys.generate(key)
    return key, awseal.keys.public_key_hex(path=key)


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSETTINGS_HOME", str(tmp_path / "awsettings"))
    for var in ("AWSETTINGS_PUBLIC_KEY", "AWSETTINGS_URL", "AWSETTINGS_SIGN",
                "AWSETTINGS_REQUIRE_SEAL", "AWSETTINGS_KEYS_URL", "AWSETTINGS_TOKEN_FILE",
                "AITHER_PORTAL_URL", "AITHER_ELYSIUM_URL"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def _sign_as(monkeypatch, key):
    monkeypatch.setenv(awseal.keys.KEY_PATH_ENV, str(key))
    return seal(PROFILE)


def test_any_enrolled_device_may_sign(home, monkeypatch):
    laptop, laptop_pub = _device(home, "laptop")
    desktop, desktop_pub = _device(home, "desktop")
    devices.write_cache([{"device_id": "laptop", "seal_pubkey": laptop_pub},
                         {"device_id": "desktop", "seal_pubkey": desktop_pub}])
    for key, pub in ((laptop, laptop_pub), (desktop, desktop_pub)):
        sealed = _sign_as(monkeypatch, key)
        assert sealed[SIGNER_KEY] == pub
        assert verify(sealed, require_seal=True) == PROFILE


def test_a_revoked_or_unknown_device_is_refused(home, monkeypatch):
    laptop, laptop_pub = _device(home, "laptop")
    stranger, _ = _device(home, "stranger")
    devices.write_cache([{"device_id": "laptop", "seal_pubkey": laptop_pub}])
    with pytest.raises(UntrustedProfileError, match="not one of this user's enrolled devices"):
        verify(_sign_as(monkeypatch, stranger), require_seal=True)


def test_naming_a_trusted_signer_does_not_launder_a_stranger_seal(home, monkeypatch):
    laptop, laptop_pub = _device(home, "laptop")
    stranger, _ = _device(home, "stranger")
    devices.write_cache([{"device_id": "laptop", "seal_pubkey": laptop_pub}])
    forged = _sign_as(monkeypatch, stranger)
    forged[SIGNER_KEY] = laptop_pub            # claim to be the laptop
    with pytest.raises(UntrustedProfileError):
        verify(forged, require_seal=True)


def test_no_trusted_keys_refuses_a_sealed_profile(home, monkeypatch):
    laptop, _ = _device(home, "laptop")
    with pytest.raises(UntrustedProfileError, match="trusts no key"):
        verify(_sign_as(monkeypatch, laptop), require_seal=True)


def test_invalid_registry_entries_are_dropped(home, monkeypatch):
    _, pub = _device(home, "laptop")
    good = {"device_id": "laptop", "seal_pubkey": pub}
    bad = [{"device_id": "x", "seal_pubkey": "zz"}, {"device_id": "y"}, "nope",
           {"device_id": "z", "seal_pubkey": "ab" * 8}]
    monkeypatch.setattr(devices, "_valid", devices._valid)

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"keys": [good, *bad]}

    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **k: R())
    assert devices.refresh("https://hub.invalid/keys", token="t") == [good]
    assert trusted_keys() == [pub]


def test_a_failed_refresh_raises_and_keeps_the_cache(home, monkeypatch):
    _, pub = _device(home, "laptop")
    devices.write_cache([{"device_id": "laptop", "seal_pubkey": pub}])
    import httpx

    def boom(*a, **k):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(httpx, "get", boom)
    with pytest.raises(CouldNotRunError):
        devices.refresh("https://hub.invalid/keys", token="t")
    assert trusted_keys() == [pub]


def test_config_file_stands_in_for_the_environment(home, monkeypatch):
    config.save({"url": "https://hub.invalid/prefs", "sign": True, "require_seal": True})
    from awsettings.profile import require_seal, resolve_url
    assert resolve_url() == "https://hub.invalid/prefs"
    assert config.flag("AWSETTINGS_SIGN") and require_seal()
    monkeypatch.setenv("AWSETTINGS_URL", "https://env.invalid/prefs")
    assert resolve_url() == "https://env.invalid/prefs"   # the environment still wins
    with pytest.raises(ValueError):
        config.save({"bogus": 1})


def test_enroll_writes_config_and_survives_an_offline_registry(home, monkeypatch, capsys):
    import httpx

    def boom(*a, **k):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(httpx, "get", boom)
    args = types.SimpleNamespace(
        url="https://hub.invalid/prefs", keys_url="https://hub.invalid/keys",
        token_file=str(home / "token"), token_command=None, no_hooks=True, root=str(home), user=False,
        domain="claude", quiet=False,
    )
    assert cli.cmd_enroll(args) == 0
    saved = json.loads(config.config_path().read_text(encoding="utf-8"))
    assert saved == {"keys_url": "https://hub.invalid/keys", "require_seal": True,
                     "sign": True, "token_file": str(home / "token"),
                     "url": "https://hub.invalid/prefs"}
    assert "not fetched yet" in capsys.readouterr().out


def test_token_command_is_the_credential_helper(home, monkeypatch, tmp_path):
    import sys

    from awsettings.profile import resolve_token
    helper = tmp_path / "helper.py"
    helper.write_text("print('  tok-123  ')", encoding="utf-8")
    config.save({"token_command": f'"{sys.executable}" "{helper}"'})
    assert resolve_token() == "tok-123"


def test_a_failing_token_command_is_fatal_not_anonymous(home, tmp_path):
    import sys

    from awsettings.profile import resolve_token
    helper = tmp_path / "signed_out.py"
    helper.write_text("import sys; sys.exit(1)", encoding="utf-8")
    config.save({"token_command": f'"{sys.executable}" "{helper}"'})
    with pytest.raises(CouldNotRunError, match="exited 1"):
        resolve_token()


def test_enroll_without_any_bearer_source_refuses(home, capsys):
    args = types.SimpleNamespace(
        url="https://hub.invalid/prefs", keys_url="https://hub.invalid/keys",
        token_file=None, token_command=None, no_hooks=True, root=str(home), user=False,
        domain="claude", quiet=False,
    )
    assert cli.cmd_enroll(args) == 1
    assert not config.config_path().exists()
