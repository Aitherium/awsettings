"""Plugins arriving through the claude_user baseline.

A plugin brings hooks. "Unmarked hooks are refused on arrival" means nothing if
whoever can write the hub blob can instead name a marketplace and enable a plugin
from it: every pulling machine would install and run that code. So, on arrival:

* ``extraKnownMarketplaces`` is refused unless the blob was SEALED (verified);
* ``enabledPlugins`` may always DISABLE, and may only ENABLE a plugin whose
  marketplace this machine already knows (its own settings, its own plugin
  registry, or a marketplace a sealed blob just delivered);
* credentials in a marketplace URL (``https://user:tok@host``) are stripped in
  both directions.
"""
from __future__ import annotations

import json

import pytest

from awsettings import core
from awsettings.cli import main
from awsettings.core import merge, redact, strip_userinfo

EVIL = {"evil": {"source": {"source": "git", "url": "https://attacker.example/p.git"}}}
GH = {"gh": {"source": {"source": "github", "repo": "o/r"}}}


# ------------------------------------------------------------------ pure merge

def test_mutation_unsealed_unknown_marketplace_is_refused():
    """The mutation: a blob anyone with hub write access could plant."""
    got = merge({}, {"extraKnownMarketplaces": EVIL,
                     "enabledPlugins": {"payload@evil": True}})
    assert "extraKnownMarketplaces" not in got
    assert got.get("enabledPlugins", {}) == {}


def test_sealed_blob_may_add_a_marketplace_and_enable_from_it():
    got = merge({}, {"extraKnownMarketplaces": GH,
                     "enabledPlugins": {"tool@gh": True}}, sealed=True)
    assert got["extraKnownMarketplaces"] == GH
    assert got["enabledPlugins"] == {"tool@gh": True}


def test_sealed_blob_still_cannot_enable_from_a_marketplace_nobody_knows():
    got = merge({}, {"enabledPlugins": {"tool@nowhere": True}}, sealed=True)
    assert got.get("enabledPlugins", {}) == {}


def test_unsealed_blob_may_enable_from_a_locally_known_marketplace():
    local = {"extraKnownMarketplaces": GH}
    got = merge(local, {"enabledPlugins": {"tool@gh": True, "x@evil": True}})
    assert got["enabledPlugins"] == {"tool@gh": True}
    got = merge({}, {"enabledPlugins": {"tool@reg": True}}, known_marketplaces={"reg"})
    assert got["enabledPlugins"] == {"tool@reg": True}


def test_disabling_is_always_accepted():
    local = {"enabledPlugins": {"tool@gh": True}}
    got = merge(local, {"enabledPlugins": {"tool@gh": False, "other@unknown": False}})
    assert got["enabledPlugins"] == {"tool@gh": False, "other@unknown": False}


def test_a_local_enable_is_never_removed_by_a_refused_arrival():
    local = {"enabledPlugins": {"mine@gh": True}, "extraKnownMarketplaces": GH}
    got = merge(local, {"enabledPlugins": {"x@evil": True}})
    assert got["enabledPlugins"] == {"mine@gh": True}


def test_a_plugin_name_without_a_marketplace_cannot_be_enabled():
    assert merge({}, {"enabledPlugins": {"bare": True}}).get("enabledPlugins", {}) == {}


def test_other_domains_are_untouched_by_the_plugin_rule():
    from awsettings.domains import get_domain
    desk = get_domain("desk")
    got = merge({}, {"enabledPlugins": {"x@evil": True}}, domain=desk)
    assert "enabledPlugins" not in got     # desk never synced it: strict inbound


# ------------------------------------------------------------------ userinfo

@pytest.mark.parametrize("url,want", [
    ("https://user:tok@host.example/r.git", "https://host.example/r.git"),
    ("https://ghp_x@host.example:8443/r.git", "https://host.example:8443/r.git"),
    ("https://host.example/r.git", "https://host.example/r.git"),
    ("git@github.com:o/r.git", "git@github.com:o/r.git"),       # scp form: no secret
    ("ssh://git:pw@host/r.git", "ssh://host/r.git"),
])
def test_strip_userinfo(url, want):
    assert strip_userinfo(url) == want


def test_marketplace_url_credentials_never_leave():
    here = {"extraKnownMarketplaces": {"m": {"source": {
        "source": "git", "url": "https://bob:s3cret@git.example/m.git"}}}}
    sent = json.dumps(redact(here))
    assert "s3cret" not in sent and "bob" not in sent
    assert "https://git.example/m.git" in sent
    assert "s3cret" in json.dumps(here)            # input not mutated


def test_marketplace_url_credentials_never_arrive():
    remote = {"extraKnownMarketplaces": {"m": {"source": {
        "source": "url", "url": "https://bob:s3cret@hub.example/marketplace.json"}}}}
    got = merge({}, remote, sealed=True)
    assert got["extraKnownMarketplaces"]["m"]["source"]["url"] == \
        "https://hub.example/marketplace.json"


# ------------------------------------------------------------------ CLI wiring

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    (tmp_path / ".claude").mkdir()
    return tmp_path


def test_user_pull_refuses_an_unsealed_marketplace_end_to_end(tmp_path, home):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"claude_user": {
        "language": "english", "extraKnownMarketplaces": EVIL,
        "enabledPlugins": {"payload@evil": True}}}), encoding="utf-8")
    assert main(["--profile", str(profile), "--user", "pull"]) == 0
    s = json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert s["language"] == "english"
    assert "extraKnownMarketplaces" not in s
    assert not s.get("enabledPlugins")


def test_user_pull_honours_the_plugin_registry(tmp_path, home):
    reg = home / ".claude" / "plugins"
    reg.mkdir()
    (reg / "known_marketplaces.json").write_text(
        json.dumps({"reg": {"source": {"source": "github", "repo": "o/reg"}}}),
        encoding="utf-8")
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"claude_user": {
        "enabledPlugins": {"tool@reg": True, "x@evil": True}}}), encoding="utf-8")
    assert main(["--profile", str(profile), "--user", "pull"]) == 0
    s = json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert s["enabledPlugins"] == {"tool@reg": True}


def test_backend_reports_whether_the_blob_was_sealed(tmp_path):
    from awsettings.profile import FileBackend
    p = tmp_path / "profile.json"
    p.write_text(json.dumps({"claude_user": {"language": "english"}}), encoding="utf-8")
    b = FileBackend(p, namespace="claude_user")
    assert b.get() == {"language": "english"}
    assert b.last_sealed is False


def test_user_push_honours_claude_config_dir(tmp_path, monkeypatch, home):
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "settings.json").write_text(json.dumps({"language": "klingon"}),
                                         encoding="utf-8")
    (home / ".claude" / "settings.json").write_text(json.dumps({"language": "wrong"}),
                                                    encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(other))
    profile = tmp_path / "profile.json"
    assert main(["--profile", str(profile), "--user", "push"]) == 0
    stored = json.loads(profile.read_text(encoding="utf-8"))
    assert stored["claude_user"]["language"] == "klingon"
    assert core.SYNCED_KEYS >= {"enabledPlugins", "extraKnownMarketplaces"}


def test_user_pull_writes_into_claude_config_dir(tmp_path, monkeypatch, home):
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(other))
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"claude_user": {"language": "english"}}),
                       encoding="utf-8")
    assert main(["--profile", str(profile), "--user", "pull"]) == 0
    assert json.loads((other / "settings.json").read_text(encoding="utf-8")) == \
        {"language": "english"}
    assert not (home / ".claude" / "settings.json").exists()

