"""A signed profile survives a server that deep-merges, and nothing unsigned rides in.

aitherium.com's /api/settings/preferences route deep-merges each PUT into what it
already holds: keys absent from the new snapshot are KEPT. A seal covers exact
bytes, so a sealed profile sent as a plain object came back with extra keys and
failed every pull. The wire form sends it as one opaque string instead; whatever
the server merges in beside that string is dropped on the way back, never applied.
"""

from __future__ import annotations

import json
import types

import pytest
from awsettings import cli
from awsettings.profile import HttpBackend
from awsettings.trust import (
    SEAL_KEY,
    SEALED_KEY,
    SIGNER_KEY,
    UntrustedProfileError,
    from_wire,
    seal,
    to_wire,
)

awseal = pytest.importorskip("awseal")

NS = "awsettings"
PROFILE = {"permissions": {"allow": ["Bash(git status:*)"], "deny": []}, "autoMode": {"allow": ["$defaults"]}}


class DeepMergeServer(HttpBackend):
    """The preferences route's PUT semantics: objects deep-merge, arrays replace."""

    def __init__(self, stored: dict | None = None):
        super().__init__("https://hub.invalid/api/settings/preferences", "t", namespace=NS)
        self.stored: dict = json.loads(json.dumps(stored or {}))

    @staticmethod
    def _merge(base, incoming):
        if not isinstance(base, dict) or not isinstance(incoming, dict):
            return incoming
        out = dict(base)
        for k, v in incoming.items():
            out[k] = DeepMergeServer._merge(base.get(k), v)
        return out

    def _request(self, method, body=None):
        if method == "PUT":
            self.stored = self._merge(self.stored, (body or {}).get("preferences") or {})
        return {"preferences": json.loads(json.dumps(self.stored))}


@pytest.fixture()
def signer(tmp_path, monkeypatch):
    key = tmp_path / "signing.key"
    awseal.keys.generate(key)
    monkeypatch.setenv(awseal.keys.KEY_PATH_ENV, str(key))
    monkeypatch.setenv("AWSETTINGS_PUBLIC_KEY", awseal.keys.public_key_hex(path=key))
    monkeypatch.setenv("AWSETTINGS_REQUIRE_SEAL", "1")
    return key


def test_wire_form_round_trips_and_leaves_unsealed_alone(signer):
    sealed = seal(PROFILE)
    wire = to_wire(sealed)
    assert set(wire) == {SEALED_KEY, SEAL_KEY, SIGNER_KEY}
    assert from_wire(wire) == sealed
    assert to_wire(PROFILE) is PROFILE and from_wire(PROFILE) is PROFILE


def test_sealed_push_survives_a_deep_merging_server(signer):
    # The server already holds keys from an OLDER push and a web edit.
    server = DeepMergeServer({NS: {"permissions": {"allow": ["Bash(rm -rf:*)"]}, "stale": 1}})
    server.put(seal(PROFILE))
    # Machine B pulls: the seal verifies and ONLY the signed payload comes back.
    assert server.get() == PROFILE


def test_keys_merged_beside_the_envelope_are_never_applied(signer):
    server = DeepMergeServer()
    server.put(seal(PROFILE))
    server.stored[NS]["permissions"] = {"allow": ["Bash(curl evil:*)"]}  # injected
    assert server.get() == PROFILE


def test_a_tampered_envelope_is_refused(signer):
    server = DeepMergeServer()
    server.put(seal(PROFILE))
    tampered = json.loads(server.stored[NS][SEALED_KEY])
    tampered["permissions"]["allow"].append("Bash(curl evil:*)")
    server.stored[NS][SEALED_KEY] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    with pytest.raises(UntrustedProfileError):
        server.get()


def test_an_unsigned_profile_is_refused_when_a_seal_is_required(signer):
    server = DeepMergeServer({NS: PROFILE})
    with pytest.raises(UntrustedProfileError):
        server.get()


def test_push_sign_seals_before_sending(signer, tmp_path, monkeypatch):
    server = DeepMergeServer()
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps(PROFILE), encoding="utf-8")
    monkeypatch.setattr(cli, "resolve", lambda *a, **k: server)
    monkeypatch.setenv("AWSETTINGS_SIGN", "1")
    monkeypatch.setenv("AWSETTINGS_HOME", str(tmp_path / "home"))
    args = types.SimpleNamespace(
        url=None, profile=None, root=str(tmp_path), user=False, domain="claude",
        quiet=True, dry_run=False, debounce=False, sign=False, prune_denies=False,
    )
    rc = cli.cmd_push(args)
    assert rc == 0
    stored = server.stored[NS]
    assert set(stored) == {SEALED_KEY, SEAL_KEY, SIGNER_KEY}
    assert server.get() == json.loads(stored[SEALED_KEY])


def test_push_sign_without_a_key_refuses_instead_of_pushing_unsigned(tmp_path, monkeypatch):
    server = DeepMergeServer()
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps(PROFILE), encoding="utf-8")
    monkeypatch.setattr(cli, "resolve", lambda *a, **k: server)
    monkeypatch.setenv(awseal.keys.KEY_PATH_ENV, str(tmp_path / "missing.key"))
    monkeypatch.setenv("AWSETTINGS_HOME", str(tmp_path / "home"))
    args = types.SimpleNamespace(
        url=None, profile=None, root=str(tmp_path), user=False, domain="claude",
        quiet=True, dry_run=False, debounce=False, sign=True, prune_denies=False,
    )
    assert cli.cmd_push(args) == 1
    assert server.stored == {}
