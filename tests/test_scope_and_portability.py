"""Scope, portability and the console: the 0.3.3 fixes, each pinned end to end.

* user scope and every project scope are separate hub namespaces, so a pull in a
  foreign checkout never adds the permission rules another repo pushed;
* a hook, status line or safety posture that names one machine's path or choice
  never leaves it and is refused on arrival;
* a cp1252 console never kills the report halfway;
* the enrolled ~/.awsettings/config.json names the remote when no env var does.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from awsettings import cli
from awsettings.core import merge, portable_hooks, redact
from awsettings.domains import USER_NAMESPACE, _normalise_remote, claude_namespace

PKG = Path(__file__).resolve().parents[1]


def _project(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    (root / ".claude").mkdir(parents=True)
    return root


# --- (2) scopes -----------------------------------------------------------------

def test_user_scope_and_project_scope_have_different_namespaces(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSETTINGS_PROJECT", "github.com/org/a")
    ns_a = claude_namespace(tmp_path)
    monkeypatch.setenv("AWSETTINGS_PROJECT", "github.com/org/b")
    ns_b = claude_namespace(tmp_path)
    assert claude_namespace(None) == USER_NAMESPACE == "claude_user"
    assert ns_a != ns_b
    assert USER_NAMESPACE not in (ns_a, ns_b)
    assert "awsettings" not in (ns_a, ns_b, USER_NAMESPACE)


def test_two_clones_of_one_repo_agree_and_credentials_never_reach_the_id():
    a = _normalise_remote("git@github.com:Org/Repo.git")
    b = _normalise_remote("https://x-token:secret@github.com/org/repo/")
    assert a == b == "github.com/org/repo"


def test_a_pull_in_a_foreign_checkout_never_adds_permissions(tmp_path, monkeypatch):
    profile = tmp_path / "profile.json"
    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))
    home_repo = _project(tmp_path, "home")
    foreign = _project(tmp_path, "foreign")
    (home_repo / ".claude/settings.local.json").write_text(json.dumps({
        "permissions": {"allow": [f"Bash(rule-{i})" for i in range(160)]},
    }), encoding="utf-8")

    monkeypatch.setenv("AWSETTINGS_PROJECT", "github.com/org/home")
    assert cli.main(["--root", str(home_repo), "--quiet", "push"]) == 0

    # Project-scope pull in another repo: nothing of home's arrives.
    monkeypatch.setenv("AWSETTINGS_PROJECT", "github.com/org/foreign")
    assert cli.main(["--root", str(foreign), "--quiet", "pull"]) == 0
    assert not (foreign / ".claude/settings.local.json").exists()

    # User-scope pull from that same foreign cwd: a different namespace entirely.
    user_file = tmp_path / "userhome" / ".claude" / "settings.json"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "userhome"))
    monkeypatch.chdir(foreign)
    assert cli.main(["--user", "--quiet", "pull"]) == 0
    assert not user_file.exists()

    # ...and the owning repo still gets its own rules back on another machine.
    other_machine = _project(tmp_path, "home-on-laptop")
    monkeypatch.setenv("AWSETTINGS_PROJECT", "github.com/org/home")
    assert cli.main(["--root", str(other_machine), "--quiet", "pull"]) == 0
    got = json.loads((other_machine / ".claude/settings.local.json").read_text(encoding="utf-8"))
    assert len(got["permissions"]["allow"]) == 160

    stored = json.loads(profile.read_text(encoding="utf-8"))
    assert "awsettings" not in stored and USER_NAMESPACE not in stored


def test_a_user_push_does_not_land_in_a_project_namespace(tmp_path, monkeypatch):
    profile = tmp_path / "profile.json"
    monkeypatch.setenv("AWSETTINGS_PROFILE", str(profile))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "userhome"))
    user_file = tmp_path / "userhome" / ".claude" / "settings.json"
    user_file.parent.mkdir(parents=True)
    user_file.write_text(json.dumps({"permissions": {"allow": ["Bash(user-rule)"]}}),
                         encoding="utf-8")
    assert cli.main(["--user", "--quiet", "push"]) == 0
    stored = json.loads(profile.read_text(encoding="utf-8"))
    assert list(stored) == [USER_NAMESPACE]


# --- (3) what may travel --------------------------------------------------------

LOCAL = {
    "permissions": {"allow": ["Bash(ls)"], "defaultMode": "bypassPermissions"},
    "hooks": {
        "SessionStart": [
            {"matcher": "", "hooks": [
                {"type": "command", "command": "awsettings --quiet pull || true",
                 "awsettings": True},
                {"type": "command", "command": "C:\\Users\\me\\hook.ps1"}]},
        ],
        "Stop": [{"matcher": "", "hooks": [
            {"type": "command", "command": "/home/me/stop.sh"}]}],
        "PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "guard", "portable": True}]}],
    },
    "statusLine": {"type": "command", "command": "C:\\Users\\me\\status.ps1"},
    "autoMode": True,
    "skipDangerousModePermissionPrompt": True,
    "sshConfigs": [{"host": "box"}],
    "remote": {"x": 1},
    "env": {"K": "v"},
    "voice": {"enabled": True},
    "apiKeyHelper": "C:\\bin\\key.exe",
}

STAY_HOME = ("statusLine", "autoMode", "skipDangerousModePermissionPrompt", "sshConfigs",
             "remote", "env", "voice", "apiKeyHelper")


def _commands(hooks):
    return sorted(h["command"] for groups in hooks.values()
                  for g in groups for h in g["hooks"])


def test_only_portable_hooks_and_no_machine_keys_leave():
    out = redact(LOCAL)
    for k in STAY_HOME:
        assert k not in out, k
    assert "defaultMode" not in out["permissions"]
    assert _commands(out["hooks"]) == ["awsettings --quiet pull || true", "guard"]
    assert "Stop" not in out["hooks"]
    text = json.dumps(out)
    assert "C:\\\\" not in text and "/home/me" not in text


def test_machine_keys_and_unmarked_hooks_are_refused_on_arrival():
    arriving = json.loads(json.dumps(LOCAL))
    arriving["someUnknownKey"] = 1
    out = merge({"permissions": {"defaultMode": "default"}}, arriving)
    for k in STAY_HOME + ("someUnknownKey",):
        assert k not in out, k
    assert out["permissions"]["defaultMode"] == "default"
    assert _commands(out["hooks"]) == ["awsettings --quiet pull || true", "guard"]


def test_arriving_portable_hooks_add_to_local_ones_never_replace_them():
    local = {"hooks": {"SessionStart": [
        {"matcher": "", "hooks": [{"type": "command", "command": "mine"}]}]}}
    remote = {"hooks": portable_hooks(LOCAL["hooks"])}
    out = merge(local, remote)
    cmds = [h["command"] for g in out["hooks"]["SessionStart"] for h in g["hooks"]]
    assert "mine" in cmds and "awsettings --quiet pull || true" in cmds
    assert merge(out, remote) == out


def test_local_machine_keys_survive_a_pull_untouched():
    out = merge(LOCAL, {"permissions": {"allow": ["Bash(new)"]}})
    for k in STAY_HOME:
        assert out[k] == LOCAL[k]
    assert out["hooks"] == LOCAL["hooks"]
    assert out["permissions"]["defaultMode"] == "bypassPermissions"


# --- (1) the console ------------------------------------------------------------

def test_a_cp1252_console_does_not_crash_the_report(tmp_path):
    root = _project(tmp_path, "r")
    profile = tmp_path / "profile.json"
    # A rule with characters cp1252 cannot encode, so `status` must print them.
    rule = "Bash(echo \u2192 \u4e16\u754c)"
    project = "example.invalid/r"
    ns = "claude_project_" + hashlib.sha256(project.encode()).hexdigest()[:12]
    profile.write_text(json.dumps({ns: {"permissions": {"allow": [rule]}}}),
                       encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONUTF8="0",
               AWSETTINGS_PROFILE=str(profile), AWSETTINGS_PROJECT=project,
               AWSETTINGS_LOCAL="1")
    done = subprocess.run([sys.executable, "-m", "awsettings.cli", "--root", str(root),
                           "status"], capture_output=True, env=env, cwd=str(PKG), timeout=120)
    err = done.stderr.decode("utf-8", "replace")
    assert "UnicodeEncodeError" not in err, err
    assert done.returncode == 0, err
    assert "a pull would apply 1 change(s)" in done.stdout.decode("utf-8", "replace")


# --- (4) the enrolled config names the remote -----------------------------------

def test_config_file_url_is_the_fallback_after_the_env_vars(monkeypatch):
    from awsettings import config
    from awsettings.profile import HttpBackend, resolve, resolve_url
    monkeypatch.delenv("AWSETTINGS_LOCAL", raising=False)
    monkeypatch.delenv("AWSETTINGS_PROFILE", raising=False)
    config.save({"url": "https://hub.invalid/prefs",
                 "token_command": f'"{sys.executable}" -c "print(123)"'})
    assert resolve_url() == "https://hub.invalid/prefs"
    backend = resolve()
    assert isinstance(backend, HttpBackend) and backend.token == "123"
    monkeypatch.setenv("AWSETTINGS_URL", "https://env.invalid/prefs")
    assert resolve_url() == "https://env.invalid/prefs"


def test_an_explicit_profile_file_beats_the_config_url(tmp_path, monkeypatch):
    from awsettings import config
    from awsettings.profile import FileBackend, resolve
    monkeypatch.delenv("AWSETTINGS_LOCAL", raising=False)
    config.save({"url": "https://hub.invalid/prefs"})
    assert isinstance(resolve(None, str(tmp_path / "p.json")), FileBackend)


def test_status_names_the_remote_even_when_the_token_helper_fails(monkeypatch, capsys,
                                                                 tmp_path):
    from awsettings import config
    monkeypatch.delenv("AWSETTINGS_LOCAL", raising=False)
    monkeypatch.delenv("AWSETTINGS_PROFILE", raising=False)
    monkeypatch.setenv("AWSETTINGS_PROJECT", "example.invalid/x")
    config.save({"url": "https://hub.invalid/prefs",
                 "token_command": f'"{sys.executable}" -c "import sys; sys.exit(1)"'})
    assert cli.main(["--root", str(_project(tmp_path, "x")), "status"]) == 2
    out = capsys.readouterr().out
    assert "remote: https://hub.invalid/prefs [claude_project_" in out
    assert "DEAD:" in out
