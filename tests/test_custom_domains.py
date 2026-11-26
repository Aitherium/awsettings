"""Tests for declarative user-defined custom domains (~/.awsettings/domains.json)."""
from __future__ import annotations

import json

import pytest
from awsettings import cli
from awsettings.core import merge, redact
from awsettings.domains import (
    CUSTOM_SECRET_FLOOR,
    all_domains,
    custom_domains_path,
    get_domain,
    remove_custom_domain,
    save_custom_domain,
)


def test_custom_domain_add_list_push_pull_remove_round_trip(tmp_path, monkeypatch, capsys):
    profile = tmp_path / "profile.json"
    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))
    cfg_a = tmp_path / "machine-a" / "myapp.json"
    cfg_b = tmp_path / "machine-b" / "myapp.json"
    cfg_a.parent.mkdir()
    cfg_b.parent.mkdir()

    # Add custom domain via CLI
    rc = cli.main([
        "domains", "add", "myapp",
        "--file", str(cfg_a),
        "--sync", "theme,editor,rules",
        "--secret", "license_key",
        "--home-subkey", "editor.cacheDir",
        "--union", "rules.allow,rules.deny",
        "--one-way", "deny",
        "--deep",
        "--summary", "MyApp user config",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "added custom domain 'myapp'" in out
    assert custom_domains_path().is_file()

    # Bare `awsettings domains` and `awsettings domains --json` still work and mark custom
    assert cli.main(["domains"]) == 0
    text_out = capsys.readouterr().out
    assert "myapp" in text_out and "[custom]" in text_out

    assert cli.main(["domains", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    by_name = {r["domain"]: r for r in rows}
    assert by_name["myapp"]["custom"] is True
    assert by_name["myapp"]["namespace"] == "custom_myapp"
    assert by_name["claude"]["custom"] is False
    assert "license_key" in by_name["myapp"]["stays_home"]
    assert "token" in by_name["myapp"]["stays_home"]
    assert "editor.cacheDir" in by_name["myapp"]["stays_home"]

    # Write machine A settings with secrets, home subkey, unknown local key, and rules
    cfg_a.write_text(json.dumps({
        "theme": "nord",
        "editor": {"fontSize": 14, "cacheDir": "/local/a/cache"},
        "rules": {"allow": ["read"], "deny": ["rm-rf"]},
        "license_key": "lic-secret-a",
        "token": "tok-secret-a",
        "scratch": "machine-a-only",
    }), encoding="utf-8")
    assert cli.main(["--domain", "myapp", "--quiet", "push"]) == 0

    # Verify profile contains only portable keys under custom_myapp namespace
    stored = json.loads(profile.read_text(encoding="utf-8"))
    assert "custom_myapp" in stored
    blob = stored["custom_myapp"]
    assert blob == {
        "theme": "nord",
        "editor": {"fontSize": 14},
        "rules": {"allow": ["read"], "deny": ["rm-rf"]},
    }

    # Pull onto machine B using per-domain env override
    cfg_b.write_text(json.dumps({
        "theme": "light",
        "editor": {"tabSize": 2, "cacheDir": "/local/b/cache"},
        "rules": {"allow": ["write"], "deny": ["drop-db"]},
        "token": "tok-secret-b",
    }), encoding="utf-8")
    monkeypatch.setenv("AWSETTINGS_CUSTOM_MYAPP_FILE", str(cfg_b))
    assert cli.main(["--domain", "myapp", "--quiet", "pull"]) == 0

    merged_b = json.loads(cfg_b.read_text(encoding="utf-8"))
    assert merged_b["theme"] == "nord"
    assert merged_b["editor"] == {"tabSize": 2, "fontSize": 14, "cacheDir": "/local/b/cache"}
    assert sorted(merged_b["rules"]["allow"]) == ["read", "write"]
    assert sorted(merged_b["rules"]["deny"]) == ["drop-db", "rm-rf"]
    assert merged_b["token"] == "tok-secret-b"

    # Remove custom domain
    assert cli.main(["domains", "remove", "myapp"]) == 0
    assert "myapp" not in all_domains()
    with pytest.raises(KeyError):
        get_domain("myapp")


def test_custom_domain_included_in_push_and_pull_all(tmp_path, monkeypatch):
    profile = tmp_path / "profile.json"
    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))
    # Point all built-in user files at absent paths so --all only touches our custom file
    for var in (
        "AWSETTINGS_DESK_FILE", "AWSETTINGS_MODS_FILE", "AWSETTINGS_MEMORY_FILE",
        "AWSETTINGS_COMPANIONS_FILE", "AWSETTINGS_DARKMATTER_FILE",
        "AWSETTINGS_NETWORK_FILE", "AWSETTINGS_PRIVACY_FILE",
        "AWSETTINGS_ANTIGRAVITY_FILE", "AWSETTINGS_AWRISE_FILE", "AWSETTINGS_AWGOV_FILE",
        "AWGIT_WT_SETTINGS",
    ):
        monkeypatch.setenv(var, str(tmp_path / "absent" / f"{var}.json"))

    cfg_a = tmp_path / "a.json"
    cfg_b = tmp_path / "b.json"
    cfg_a.write_text(json.dumps({"accent": "teal", "api_key": "secret"}), encoding="utf-8")

    save_custom_domain("palette", {
        "path": str(cfg_a),
        "synced_keys": ["accent"],
    })
    assert cli.main(["--quiet", "push", "--all"]) == 0
    stored = json.loads(profile.read_text(encoding="utf-8"))
    assert stored["custom_palette"] == {"accent": "teal"}

    monkeypatch.setenv("AWSETTINGS_CUSTOM_PALETTE_FILE", str(cfg_b))
    assert cli.main(["--quiet", "pull", "--all"]) == 0
    assert json.loads(cfg_b.read_text(encoding="utf-8")) == {"accent": "teal"}


def test_custom_domain_cannot_shadow_builtin_or_remove_builtin(tmp_path, capsys):
    for name in ("claude", "antigravity", "awrise", "awgov", "desk"):
        rc = cli.main([
            "domains", "add", name,
            "--file", str(tmp_path / f"{name}.json"),
            "--sync", "theme",
        ])
        assert rc == 1
        assert "REFUSED" in capsys.readouterr().out

        rc_rm = cli.main(["domains", "remove", name])
        assert rc_rm == 1
        assert "REFUSED" in capsys.readouterr().out


def test_custom_domain_rejects_invalid_names_and_secret_floor_in_sync(tmp_path, capsys):
    for bad_name in ("../evil", "My App", "1starts-digit", "has.dot", "a/b"):
        with pytest.raises(ValueError):
            save_custom_domain(bad_name, {"path": str(tmp_path / "x.json"), "synced_keys": ["a"]})

    for secret_key in sorted(CUSTOM_SECRET_FLOOR):
        rc = cli.main([
            "domains", "add", "safetest",
            "--file", str(tmp_path / "x.json"),
            "--sync", f"theme,{secret_key}",
        ])
        assert rc == 1
        assert "REFUSED" in capsys.readouterr().out


def test_hand_edited_domains_json_cannot_bypass_security_invariants(tmp_path):
    """Even if a user hand-edits ~/.awsettings/domains.json to shadow a built-in or put
    'token' into synced_keys, the loader fails closed."""
    reg = custom_domains_path()
    reg.parent.mkdir(parents=True, exist_ok=True)
    reg.write_text(json.dumps({
        "version": 1,
        "domains": {
            # Attempt to shadow a built-in domain
            "awgov": {
                "path": str(tmp_path / "hijack.json"),
                "synced_keys": ["permits"],
            },
            # Attempt to sync a floor secret key
            "sneaky": {
                "path": str(tmp_path / "sneaky.json"),
                "synced_keys": ["theme", "token", "env", "apiKey"],
            },
            # Only secret keys -> dropped completely
            "onlysecret": {
                "path": str(tmp_path / "onlysecret.json"),
                "synced_keys": ["token"],
            },
        },
    }), encoding="utf-8")

    # Built-in awgov is untouched
    gov = get_domain("awgov")
    assert gov.custom is False
    assert gov.namespace == "awgov_user"
    assert "permits" in gov.secret_keys

    # Sneaky had floor secret keys stripped from synced_keys and added to secret_keys
    sneaky = get_domain("sneaky")
    assert sneaky.custom is True
    assert sneaky.strict_inbound is True
    assert sneaky.hookable is False
    assert sneaky.synced_keys == frozenset({"theme"})
    assert CUSTOM_SECRET_FLOOR.issubset(sneaky.secret_keys)

    sent = redact({"theme": "dark", "token": "t", "env": {"A": "1"}, "apiKey": "k"}, domain=sneaky)
    assert sent == {"theme": "dark"}

    merged = merge(
        {"theme": "light", "token": "mine"},
        {"theme": "dark", "token": "evil", "apiKey": "evil", "injected": True},
        domain=sneaky,
    )
    assert merged == {"theme": "dark", "token": "mine"}

    # onlysecret had no non-secret keys left -> ignored
    assert "onlysecret" not in all_domains()


def test_custom_domain_one_way_deny_and_prune_denies(tmp_path):
    save_custom_domain("firewall", {
        "path": str(tmp_path / "fw.json"),
        "synced_keys": ["rules"],
        "union_arrays": ["rules.allow", "rules.deny"],
        "one_way": ["deny"],
        "deep": True,
    })
    dom = get_domain("firewall")
    local = {"rules": {"allow": ["a"], "deny": ["block-x"]}}
    remote = {"rules": {"allow": ["b"], "deny": []}}

    default_pull = merge(local, remote, domain=dom)
    assert default_pull["rules"]["deny"] == ["block-x"]
    assert sorted(default_pull["rules"]["allow"]) == ["a", "b"]

    pruned_pull = merge(local, remote, prune_denies=True, domain=dom)
    assert pruned_pull["rules"]["deny"] == []


def test_malformed_domains_json_does_not_break_builtins_and_refuses_overwrite(tmp_path):
    reg = custom_domains_path()
    reg.parent.mkdir(parents=True, exist_ok=True)
    reg.write_text("{ broken json", encoding="utf-8")

    # Built-ins still work fine
    assert "claude" in all_domains()
    assert get_domain("antigravity").namespace == "antigravity_user"

    # Writing refuses rather than clobbering the half-edited file
    rc = cli.main([
        "domains", "add", "fresh",
        "--file", str(tmp_path / "fresh.json"),
        "--sync", "theme",
    ])
    assert rc == 2
    assert reg.read_text(encoding="utf-8") == "{ broken json"


def test_duplicate_custom_domain_requires_force(tmp_path, capsys):
    save_custom_domain("app1", {"path": str(tmp_path / "a.json"), "synced_keys": ["k1"]})
    assert cli.main([
        "domains", "add", "app1",
        "--file", str(tmp_path / "b.json"),
        "--sync", "k2",
    ]) == 1
    assert "REFUSED" in capsys.readouterr().out

    assert cli.main([
        "domains", "add", "app1",
        "--file", str(tmp_path / "b.json"),
        "--sync", "k2",
        "--force",
    ]) == 0
    dom = get_domain("app1")
    assert dom.synced_keys == frozenset({"k2"})
    assert dom.locate(None) == (tmp_path / "b.json").resolve()
    assert remove_custom_domain("app1") is True
