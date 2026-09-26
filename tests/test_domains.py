"""Domains, the preferences envelope, and the write that must be seen to land.

The fake server below is not a convenience mock. It reproduces, line for line in
behaviour, the three things a real `preferences`-shaped endpoint does that the
original client never accounted for: it reads ONLY `body["preferences"]`, it
answers 200 whatever it found there, and it drops credential-NAMED keys on the way
in. Each of those turned a push into a green run that stored nothing.
"""
from __future__ import annotations

import json

import pytest
from awsettings import cli
from awsettings.core import diff_summary, merge, redact
from awsettings.domains import desk_cast_path, get_domain
from awsettings.profile import (
    FileBackend,
    HttpBackend,
    ProfileRejectedError,
    missing_paths,
    resolve_token,
)
from awsettings.store import CouldNotRunError

DESK = get_domain("desk")

CREDENTIAL_TERMS = {"apikey", "key", "secret", "password", "token", "auth", "credentials"}


def _credential_named(key: str) -> bool:
    terms = key.replace("-", "_").lower().split("_")
    return any(t in CREDENTIAL_TERMS for t in terms)


def _strip(value):
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items() if not _credential_named(k)}
    return value


class PreferencesServer(HttpBackend):
    """An endpoint of the `{"preferences": {...}}` shape, in memory."""

    def __init__(self, namespace: str, stored: dict | None = None, envelope: str = "auto"):
        super().__init__("https://hub.invalid/api/settings/preferences", "t",
                         namespace=namespace, envelope=envelope)
        self.stored: dict = dict(stored or {})
        self.bodies: list = []

    def _request(self, method, body=None):
        if method == "GET":
            return {"preferences": json.loads(json.dumps(self.stored))}
        self.bodies.append(body)
        incoming = _strip((body or {}).get("preferences") or {})
        for ns, blob in incoming.items():
            self.stored[ns] = {**self.stored.get(ns, {}), **blob}
        return {"ok": True, "preferences": json.loads(json.dumps(self.stored))}


class BareServer(HttpBackend):
    def __init__(self, namespace: str):
        super().__init__("https://bare.invalid/profile", None, namespace=namespace)
        self.stored: dict = {}

    def _request(self, method, body=None):
        if method == "GET":
            return dict(self.stored)
        self.stored.update(body or {})
        return {}


# --- the envelope ------------------------------------------------------------

def test_the_old_bare_body_is_a_silent_no_op_against_a_preferences_server():
    """The defect, reproduced: force the ORIGINAL wire format and watch the server
    answer OK while storing nothing. This is what `confirm` now refuses."""
    server = PreferencesServer("awsettings", envelope="bare")
    with pytest.raises(ProfileRejectedError) as err:
        # `bare` sends {"awsettings": {...}}; the server reads body["preferences"].
        server._shape = "bare"
        reply = server._request("PUT", {"awsettings": {"outputStyle": "x"}})
        assert reply["ok"] is True and server.stored == {}, "the no-op did not reproduce"
        server._shape = "preferences"
        server._confirm({"outputStyle": "x"}, reply)
    assert "stored nothing" in str(err.value)


def test_auto_detects_the_preferences_shape_and_the_write_lands():
    server = PreferencesServer("awdesk", stored={"adk": {"llm": "local"}})
    server.put({"voice": {"volume": 0.3}})
    assert server.bodies == [{"preferences": {"awdesk": {"voice": {"volume": 0.3}}}}]
    assert server.get() == {"voice": {"volume": 0.3}}
    # Somebody else's namespace is neither read as ours nor disturbed.
    assert server.stored["adk"] == {"llm": "local"}


def test_an_absent_namespace_is_empty_never_the_whole_preferences_object():
    server = PreferencesServer("awdesk", stored={"adk": {"llm": "local"}, "mcp": {"s": 1}})
    assert server.get() == {}


def test_a_key_the_server_drops_is_refused_by_path_not_reported_as_pushed():
    server = PreferencesServer("awdesk")
    snapshot = {"authors": {"token-service": {"volume": 0.5}, "aitheros": {"volume": 1}}}
    with pytest.raises(ProfileRejectedError) as err:
        server.put(snapshot)
    assert err.value.dropped == ["authors.token-service"]


def test_a_bare_server_still_works_exactly_as_before():
    server = BareServer("awsettings")
    server.put({"outputStyle": "aither"})
    assert server.stored == {"awsettings": {"outputStyle": "aither"}}
    assert server.get() == {"outputStyle": "aither"}


def test_missing_paths_judges_keys_never_values():
    assert missing_paths({"a": {"b": 1}}, {"a": {"b": 2}}) == []
    assert missing_paths({"a": {"b": 1, "c": 2}}, {"a": {"b": 1}}) == ["a.c"]
    assert missing_paths({"a": {"b": 1}}, {"a": "flattened"}) == ["a"]


def test_an_unknown_envelope_is_could_not_run_not_a_guess():
    with pytest.raises(CouldNotRunError):
        HttpBackend("https://x.invalid", None, envelope="yaml")


# --- the engine, per domain ---------------------------------------------------

def test_a_nested_credential_may_not_arrive():
    out = merge({"sandbox": {"enabled": True}},
                {"sandbox": {"credentials": {"envVars": [{"name": "PLANTED"}]}}})
    assert "credentials" not in out["sandbox"]
    assert out["sandbox"]["enabled"] is True


def test_desk_redact_keeps_topology_and_migration_state_at_home():
    local = {"version": 1, "migratedLegacyAt": "2026-09-18",
             "voice": {"volume": 0.4, "endpoint": {"host": "127.0.0.1", "port": 8084}},
             "scratch": True}
    assert redact(local, domain=DESK) == {"version": 1, "voice": {"volume": 0.4}}


def test_desk_merge_is_leaf_level_so_two_machines_editing_one_actor_both_survive():
    here = {"actors": {"mcp:speak": {"voice": "onyx"}}}
    there = {"actors": {"mcp:speak": {"volume": 0.5}, "desk:drop": {"speak": False}}}
    out = merge(here, there, domain=DESK)
    assert out["actors"] == {"mcp:speak": {"voice": "onyx", "volume": 0.5},
                             "desk:drop": {"speak": False}}
    assert here == {"actors": {"mcp:speak": {"voice": "onyx"}}}, "merge mutated its input"


def test_desk_merge_refuses_an_arriving_endpoint_and_an_unknown_key():
    here = {"voice": {"endpoint": {"host": "127.0.0.1", "port": 8084}}}
    there = {"voice": {"endpoint": {"host": "elsewhere", "port": 1}, "muted": True},
             "injected": {"x": 1}}
    out = merge(here, there, domain=DESK)
    assert out == {"voice": {"endpoint": {"host": "127.0.0.1", "port": 8084}, "muted": True}}


def test_desk_behaviour_sections_sync_and_the_sync_section_never_does():
    """`sync` holds a profile path and a bearer-file path ON ONE MACHINE. If a profile
    could deliver one, whoever can write the profile could re-point a machine's sync
    target -- and the file its bearer is read from -- at a server of their choosing."""
    local = {"version": 1, "models": {"commandProfile": "opus"},
             "prompts": {"commandAppend": "Be brief."}, "vision": {"enabled": False},
             "sync": {"enabled": True, "profile": "D:/mine.json", "tokenFile": "C:/bearer"}}
    sent = redact(local, domain=DESK)
    assert sent == {"version": 1, "models": {"commandProfile": "opus"},
                    "prompts": {"commandAppend": "Be brief."}, "vision": {"enabled": False}}

    hostile = {"sync": {"enabled": True, "url": "https://evil.invalid/p", "tokenFile": "C:/bearer"},
               "models": {"commandProfile": "sonnet"}}
    out = merge(local, hostile, domain=DESK)
    assert out["sync"] == local["sync"], "an ARRIVING sync section re-pointed this machine"
    assert out["models"] == {"commandProfile": "sonnet"}     # control: the rest still merges


def test_an_explicit_null_travels_because_a_merge_cannot_carry_a_delete():
    out = merge({"actors": {"a": {"volume": 0.2}}}, {"actors": {"a": {"volume": None}}},
                domain=DESK)
    assert out["actors"]["a"] == {"volume": None}


def test_the_desk_diff_names_the_field():
    before = {"voice": {"volume": 1}}
    after = merge(before, {"voice": {"volume": 0.3, "muted": True}}, domain=DESK)
    assert diff_summary(before, after, domain=DESK) == [
        "+ voice.muted = true", "~ voice.volume: 1 -> 0.3"]


def test_the_claude_domain_is_unchanged_a_record_still_replaces_one_level_down():
    out = merge({"statusLine": {"type": "command", "command": "a"}},
                {"statusLine": {"command": "b"}})
    assert out["statusLine"] == {"type": "command", "command": "b"}


def test_an_unknown_domain_raises():
    with pytest.raises(KeyError):
        get_domain("desc")


# --- the two domains share one profile file without touching each other -------

def test_two_namespaces_in_one_file_do_not_stamp_over_each_other(tmp_path):
    profile = tmp_path / "profile.json"
    FileBackend(profile, namespace="awsettings").put({"outputStyle": "aither"})
    FileBackend(profile, namespace="awdesk").put({"voice": {"volume": 0.2}})
    assert FileBackend(profile, namespace="awsettings").get() == {"outputStyle": "aither"}
    assert FileBackend(profile, namespace="awdesk").get() == {"voice": {"volume": 0.2}}


# --- the CLI: a config file another shell, agent or app can manage ------------

@pytest.fixture()
def desk(tmp_path, monkeypatch):
    cast = tmp_path / "Desk" / "cast.json"
    monkeypatch.setenv("AWSETTINGS_DESK_FILE", str(cast))
    monkeypatch.setenv("AWSETTINGS_PROFILE", str(tmp_path / "profile.json"))
    monkeypatch.delenv("AWSETTINGS_URL", raising=False)
    monkeypatch.delenv("AWSETTINGS_DOMAIN", raising=False)
    return cast


def test_the_desk_file_override_wins_and_the_app_s_own_variable_is_honoured(
        tmp_path, monkeypatch):
    monkeypatch.delenv("AWSETTINGS_DESK_FILE", raising=False)
    monkeypatch.setenv("DESK_CAST_FILE", str(tmp_path / "x.json"))
    assert desk_cast_path() == (tmp_path / "x.json").resolve()


def test_set_get_push_pull_round_trip_between_two_machines(desk, tmp_path, monkeypatch, capsys):
    assert cli.main(["--domain", "desk", "set", "voice.volume", "0.35"]) == 0
    assert cli.main(["--domain", "desk", "set", 'actors."mcp:speak".volume', "1.5"]) == 0
    assert cli.main(["--domain", "desk", "set", "voice.defaultVoice", "onyx"]) == 0
    data = json.loads(desk.read_text(encoding="utf-8"))
    assert data == {"version": 1,
                    "voice": {"volume": 0.35, "defaultVoice": "onyx"},
                    "actors": {"mcp:speak": {"volume": 1.5}}}
    capsys.readouterr()
    assert cli.main(["--domain", "desk", "get", "voice.volume"]) == 0
    assert capsys.readouterr().out.strip() == "0.35"
    assert cli.main(["--domain", "desk", "--quiet", "push"]) == 0

    # Machine B: its own file, with a field A never set.
    other = tmp_path / "B" / "cast.json"
    other.parent.mkdir()
    other.write_text(json.dumps({"version": 1, "actors": {"mcp:speak": {"voice": "echo"}}}),
                     encoding="utf-8")
    monkeypatch.setenv("AWSETTINGS_DESK_FILE", str(other))
    assert cli.main(["--domain", "desk", "--quiet", "pull"]) == 0
    merged = json.loads(other.read_text(encoding="utf-8"))
    assert merged["actors"]["mcp:speak"] == {"voice": "echo", "volume": 1.5}
    assert merged["voice"]["volume"] == 0.35


def test_get_of_an_unset_path_exits_1_and_an_unknown_domain_exits_2(desk):
    assert cli.main(["--domain", "desk", "get", "voice.volume"]) == 1
    assert cli.main(["--domain", "nope", "status"]) == 2


def test_hooks_are_refused_for_a_domain_that_has_none(desk):
    assert cli.main(["--domain", "desk", "hook", "install"]) == 1


def test_a_malformed_cast_file_is_never_overwritten_by_set(desk):
    desk.parent.mkdir(parents=True)
    desk.write_text("{ half an edit", encoding="utf-8")
    assert cli.main(["--domain", "desk", "set", "voice.volume", "0.1"]) == 2
    assert desk.read_text(encoding="utf-8") == "{ half an edit"


# --- the token ----------------------------------------------------------------

def test_a_token_file_is_read_and_a_missing_one_is_fatal_not_anonymous(tmp_path, monkeypatch):
    monkeypatch.delenv("AWSETTINGS_TOKEN", raising=False)
    token = tmp_path / "bearer"
    token.write_text("  abc123\n", encoding="utf-8")
    monkeypatch.setenv("AWSETTINGS_TOKEN_FILE", str(token))
    assert resolve_token() == "abc123"
    monkeypatch.setenv("AWSETTINGS_TOKEN_FILE", str(tmp_path / "gone"))
    with pytest.raises(CouldNotRunError):
        resolve_token()


# --- the portal sign-in (adk) ---------------------------------------------------

def _clear_hub_env(monkeypatch, tmp_path):
    for var in ("AWSETTINGS_URL", "AITHER_PORTAL_URL", "AITHER_ELYSIUM_URL",
                "AWSETTINGS_TOKEN", "AWSETTINGS_TOKEN_FILE", "AWSETTINGS_LOCAL",
                "AWSETTINGS_PROFILE", "AITHER_PORTAL_TOKEN", "AITHERIUM_API_KEY",
                "AITHER_API_KEY", "AITHER_SYNC_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    # No enrolled config file either: point awsettings' home somewhere empty.
    monkeypatch.setenv("AWSETTINGS_HOME", str(tmp_path / "awsettings"))


def _fake_adk(monkeypatch, token):
    import sys
    import types

    creds = types.SimpleNamespace(access_token=token)
    auth = types.ModuleType("adk.auth")
    auth.resolve_credentials = lambda: creds
    adk = types.ModuleType("adk")
    adk.auth = auth
    monkeypatch.setitem(sys.modules, "adk", adk)
    monkeypatch.setitem(sys.modules, "adk.auth", auth)


def test_a_portal_sign_in_selects_the_hub_and_supplies_the_bearer(monkeypatch, tmp_path):
    from awsettings.profile import DEFAULT_HUB_URL, resolve_url
    _clear_hub_env(monkeypatch, tmp_path)
    _fake_adk(monkeypatch, "portal-bearer")
    assert resolve_url() == DEFAULT_HUB_URL
    assert resolve_token() == "portal-bearer"


def test_no_sign_in_keeps_the_local_file(monkeypatch, tmp_path):
    import sys

    from awsettings.profile import resolve_url
    _clear_hub_env(monkeypatch, tmp_path)
    monkeypatch.setitem(sys.modules, "adk", None)  # adk not installed
    monkeypatch.setitem(sys.modules, "adk.auth", None)
    assert resolve_url() is None
    assert resolve_token() is None


def test_the_local_root_placeholder_is_not_a_portal_login(monkeypatch, tmp_path):
    from awsettings.profile import resolve_url
    _clear_hub_env(monkeypatch, tmp_path)
    _fake_adk(monkeypatch, "aither_root_local")
    assert resolve_url() is None


def test_awsettings_local_forces_the_file_even_when_signed_in(monkeypatch, tmp_path):
    from awsettings.profile import resolve_url
    _clear_hub_env(monkeypatch, tmp_path)
    _fake_adk(monkeypatch, "portal-bearer")
    monkeypatch.setenv("AWSETTINGS_LOCAL", "1")
    assert resolve_url() is None


def test_an_explicit_profile_file_beats_the_portal_default(monkeypatch, tmp_path):
    from awsettings.profile import FileBackend, resolve
    _clear_hub_env(monkeypatch, tmp_path)
    _fake_adk(monkeypatch, "portal-bearer")
    assert isinstance(resolve(None, str(tmp_path / "p.json")), FileBackend)
    monkeypatch.setenv("AWSETTINGS_PROFILE", str(tmp_path / "q.json"))
    assert isinstance(resolve(None, None), FileBackend)


def test_an_explicit_host_env_still_wins(monkeypatch, tmp_path):
    from awsettings.profile import resolve_url
    _clear_hub_env(monkeypatch, tmp_path)
    _fake_adk(monkeypatch, "portal-bearer")
    monkeypatch.setenv("AWSETTINGS_URL", "https://example.invalid/prefs")
    assert resolve_url() == "https://example.invalid/prefs"
