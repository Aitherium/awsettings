"""`awsettings preset` -- named user presets, and the claude_user baseline they push.

Every test runs against a tmp HOME: a preset test that touched the real
~/.claude/settings.json would be the bug it exists to prevent.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from awsettings import preset as pre
from awsettings.cli import main


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    for var in ("AWSETTINGS_URL", "AWSETTINGS_PROFILE", "AWSETTINGS_SIGN",
                "AITHER_PORTAL_TOKEN", "AITHER_SYNC_TOKEN", "AWSETTINGS_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWSETTINGS_LOCAL", "1")
    (tmp_path / ".claude").mkdir()
    return tmp_path


def _settings(home: Path) -> dict:
    return json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))


def _write(home: Path, name: str, data: dict) -> Path:
    path = home / ".claude" / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_shipped_presets_are_writable():
    for name, preset in pre.PRESETS.items():
        assert pre.refused_paths(preset) == [], name


def test_shipped_presets_carry_nothing_machine_specific():
    text = json.dumps(pre.PRESETS)
    for needle in ("C:\\", "C:/", "/home/", "/Users/", "AitherOS-Fresh",
                   "Aitherium/AitherOS", "\"directory\""):
        assert needle not in text, needle


def test_apply_writes_every_portable_key_and_the_keybinding(home, capsys):
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    s = _settings(home)
    want = pre.PRESETS["aitherium-claude"]["settings"]
    for key, value in want.items():
        assert s[key] == value, key
    kb = json.loads((home / ".claude" / "keybindings.json").read_text(encoding="utf-8"))
    assert {"context": "Chat", "bindings": {"ctrl+alt+v": "voice:pushToTalk"}} in kb["bindings"]
    assert "+" in capsys.readouterr().out            # a diff was printed


def test_apply_never_clobbers_a_user_value_and_keeps_secrets(home, capsys):
    _write(home, "settings.json", {
        "language": "french",
        "voice": {"enabled": False},
        "fallbackModel": ["opus"],
        "env": {"TOKEN": "keep-me"},
        "autoMode": {"environment": ["mine"]},
        "hooks": {"Stop": []},
    })
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    s = _settings(home)
    assert s["language"] == "french"
    assert s["voice"] == {"enabled": False, "mode": "tap"}       # missing leaf filled
    assert s["fallbackModel"] == ["opus", "sonnet"]              # union, order kept
    assert s["env"] == {"TOKEN": "keep-me"}
    assert s["autoMode"] == {"environment": ["mine"]}
    assert s["hooks"] == {"Stop": []}
    out = capsys.readouterr().out
    assert "kept (yours): settings.json: language" in out
    assert "keep-me" not in out                                  # env value never printed
    assert "machine" not in out


def test_force_replaces_user_values_but_not_refused_keys(home):
    _write(home, "settings.json", {"language": "french", "env": {"A": "1"}})
    assert main(["preset", "apply", "aitherium-claude", "--force"]) == 0
    s = _settings(home)
    assert s["language"] == "english"
    assert s["env"] == {"A": "1"}


def test_user_keybinding_kept_unless_forced(home):
    _write(home, "keybindings.json", {"bindings": [
        {"context": "Chat", "bindings": {"ctrl+alt+v": "chat:submit", "ctrl+k": "x:y"}}]})
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    kb = json.loads((home / ".claude" / "keybindings.json").read_text(encoding="utf-8"))
    assert kb["bindings"][0]["bindings"] == {"ctrl+alt+v": "chat:submit", "ctrl+k": "x:y"}
    assert main(["preset", "apply", "aitherium-claude", "--force"]) == 0
    kb = json.loads((home / ".claude" / "keybindings.json").read_text(encoding="utf-8"))
    assert kb["bindings"][0]["bindings"]["ctrl+alt+v"] == "voice:pushToTalk"
    assert kb["bindings"][0]["bindings"]["ctrl+k"] == "x:y"


def test_backup_is_taken_before_the_write(home):
    original = {"language": "english", "theme": "dark"}
    _write(home, "settings.json", original)
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    backups = list((home / ".claude").glob("settings.json.awsettings-bak-*"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8")) == original


def test_dry_run_writes_nothing(home):
    assert main(["preset", "apply", "aitherium-claude", "--dry-run"]) == 0
    assert not (home / ".claude" / "settings.json").exists()
    assert not (home / ".claude" / "keybindings.json").exists()


def test_second_apply_is_a_noop(home, capsys):
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    capsys.readouterr()
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    assert "nothing to do" in capsys.readouterr().out
    assert len(list((home / ".claude").glob("*.awsettings-bak-*"))) == 0


@pytest.mark.parametrize("bad", [
    {"autoMode": {"environment": ["planted"]}},
    {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "x"}]}]}},
    {"env": {"X": "1"}},
    {"permissions": {"defaultMode": "bypassPermissions"}},
    {"apiKeyHelper": "cat /tmp/key"},
    {"statusLine": {"type": "command", "command": "x"}},
    {"somethingNew": 1},
])
def test_mutation_a_refused_key_in_the_preset_refuses_the_whole_write(
        home, monkeypatch, capsys, bad):
    """The mutation test: add ONE forbidden key to the shipped preset and nothing
    at all may be written -- not even the portable keys beside it -- and exit 1."""
    mutated = copy.deepcopy(pre.PRESETS)
    mutated["aitherium-claude"]["settings"].update(bad)
    monkeypatch.setattr(pre, "PRESETS", mutated)
    _write(home, "settings.json", {"theme": "dark"})
    rc = main(["preset", "apply", "aitherium-claude", "--force"])
    assert rc == 1
    assert _settings(home) == {"theme": "dark"}
    assert not (home / ".claude" / "keybindings.json").exists()
    assert not list((home / ".claude").glob("*.awsettings-bak-*"))
    assert "REFUSED" in capsys.readouterr().out


def test_malformed_settings_is_could_not_judge(home):
    (home / ".claude" / "settings.json").write_text("{ half", encoding="utf-8")
    assert main(["preset", "apply", "aitherium-claude"]) == 2
    assert (home / ".claude" / "settings.json").read_text(encoding="utf-8") == "{ half"


def test_unknown_preset_is_could_not_judge(home):
    assert main(["preset", "apply", "nope"]) == 2


def test_every_portable_preset_key_rides_the_user_sync_except_voice():
    """The wiring: a preset key the claude domain does not sync would apply on one
    machine and never reach the next -- a baseline with a hole in it."""
    from awsettings.core import HOME_KEYS, SYNCED_KEYS
    assert pre.PORTABLE_KEYS - SYNCED_KEYS == {"voice"}
    assert "voice" in HOME_KEYS
    assert pre.NAMESPACE == "claude_user"
    assert not (pre.NEVER_KEYS & SYNCED_KEYS - {"hooks", "permissions", "sandbox"})


def test_redact_and_merge_keep_local_path_marketplaces_home():
    from awsettings.core import merge, redact
    here = {"language": "english", "autoMode": {"x": 1}, "env": {"T": "s"},
            "extraKnownMarketplaces": {
                "local": {"source": {"source": "directory", "path": "/on/one/box"}},
                "gh": {"source": {"source": "github", "repo": "o/r"}}}}
    sent = redact(here)
    assert sent == {"language": "english", "extraKnownMarketplaces": {
        "gh": {"source": {"source": "github", "repo": "o/r"}}}}
    # arriving (from a SEALED blob -- an unsealed one adds no marketplace at all,
    # test_plugin_trust.py): a local-path entry is refused, and a local checkout is
    # not replaced
    mine = {"extraKnownMarketplaces": {
        "awsh": {"source": {"source": "directory", "path": "/dev/checkout"}}}}
    got = merge(mine, {"extraKnownMarketplaces": {
        "awsh": {"source": {"source": "github", "repo": "o/awsh"}},
        "evil": {"source": {"source": "directory", "path": "/tmp/planted"}},
        "gh": {"source": {"source": "github", "repo": "o/r"}}}}, sealed=True)
    assert got["extraKnownMarketplaces"] == {
        "awsh": {"source": {"source": "directory", "path": "/dev/checkout"}},
        "gh": {"source": {"source": "github", "repo": "o/r"}}}


def test_push_then_pull_makes_it_the_baseline_on_the_next_machine(tmp_path, monkeypatch,
                                                                   home):
    profile = tmp_path / "profile.json"
    # machine A: an existing directory-sourced marketplace must not travel
    _write(home, "settings.json", {"extraKnownMarketplaces": {
        "awsh": {"source": {"source": "directory", "path": "/box/a/claude_mod"}}},
        "autoMode": {"environment": ["machine A only"]}})
    assert main(["--profile", str(profile), "preset", "apply", "aitherium-claude",
                 "--push"]) == 0
    stored = json.loads(profile.read_text(encoding="utf-8"))
    assert set(stored) == {"claude_user"}
    text = json.dumps(stored)
    assert "/box/a" not in text and "machine A only" not in text
    assert stored["claude_user"]["language"] == "english"
    # a plain user push afterwards writes the SAME baseline, not a rival one
    assert main(["--profile", str(profile), "--user", "push"]) == 0
    assert json.loads(profile.read_text(encoding="utf-8")) == stored

    # machine B: a fresh home pulls it
    b = tmp_path / "b"
    (b / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(b))
    monkeypatch.setenv("USERPROFILE", str(b))
    _write(b, "settings.json", {"theme": "light"})
    assert main(["--profile", str(profile), "preset", "pull"]) == 0
    s = _settings(b)
    assert s["theme"] == "light"
    assert s["language"] == "english"
    # an UNSEALED blob may not switch on a plugin from a marketplace B does not
    # know: a plugin brings hooks (test_plugin_trust.py)
    assert "enabledPlugins" not in s
    assert "autoMode" not in s and "voice" not in s


def test_pull_refuses_an_automode_planted_in_the_baseline(tmp_path, home):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"claude_user": {
        "language": "english", "autoMode": {"environment": ["planted"]},
        "env": {"X": "planted"}, "permissions": {"defaultMode": "bypassPermissions"}}}),
        encoding="utf-8")
    assert main(["--profile", str(profile), "preset", "pull"]) == 0
    s = _settings(home)
    assert s == {"language": "english", "permissions": {}} or s == {"language": "english"}


def test_claude_config_dir_is_honoured(tmp_path, monkeypatch, home):
    other = tmp_path / "elsewhere"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(other))
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    assert (other / "settings.json").is_file()
    assert not (home / ".claude" / "settings.json").exists()


def test_a_marketplace_entry_is_merged_whole_never_leaf_by_leaf(home, capsys):
    """Measured on the first live dry-run: leaf filling turned a directory-sourced
    marketplace into {source: directory, path, repo, sparsePaths} -- a broken entry."""
    mine = {"awsh": {"source": {"source": "directory", "path": "/x/claude_mod"}}}
    _write(home, "settings.json", {"extraKnownMarketplaces": mine})
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    assert _settings(home)["extraKnownMarketplaces"] == mine
    assert "extraKnownMarketplaces.awsh" in capsys.readouterr().out


def test_a_reworded_tip_with_the_same_id_is_not_added_twice(home):
    _write(home, "settings.json", {"spinnerTipsOverride": {
        "label": "aw", "tips": [{"id": "awm", "text": "my own words", "cooldownSessions": 3}]}})
    assert main(["preset", "apply", "aitherium-claude"]) == 0
    tips = _settings(home)["spinnerTipsOverride"]["tips"]
    assert [t["text"] for t in tips if t["id"] == "awm"] == ["my own words"]
    assert len({t["id"] for t in tips}) == len(tips)
