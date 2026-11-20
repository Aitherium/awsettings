"""The platform-first guard, exercised from INSIDE the package.

The file under test is generated (byte-identically) from
AitherOS/dev/tools/platform_first_rules.py by gen_platform_first.py. The
monorepo asserts the copies never drift; this asserts the copy that ships as
`awsettings-guard` actually decides, so a packaging mistake (a module the wheel
does not carry, a console script that cannot start) is caught here rather than
on the machine of whoever first needed the guard.

The rule set is the owner's, 2026-11-18: never hand-roll a script, never start a
bare process, find-and-extend first. Each deny case below is a command that
actually ran that day.
"""
from __future__ import annotations

import io
import json

from awsettings import platform_first as pf


def _payload(command: str, cwd: str | None = None, tool: str = "Bash") -> dict:
    out = {"tool_name": tool, "tool_input": {"command": command}, "session_id": "test"}
    if cwd:
        out["cwd"] = cwd
    return out


def _clean_env() -> dict:
    return {"PATH": ""}


def test_the_shipped_table_is_the_owner_rule_set():
    assert [r["id"] for r in pf.RULES] == [f"D{i}" for i in range(1, 8)]
    for rule in pf.RULES:
        assert rule["sample"] and rule["scope"] in ("raw", "masked", "step")


def test_denies_a_hand_rolled_render(tmp_path):
    got = pf.decide(
        _payload('Start-Process -FilePath "C:\\Program Files\\Git\\bin\\bash.exe" '
                 "-ArgumentList 'E:/Aither-Media/x/shoot/v10.1/render.sh' -WindowStyle Hidden",
                 str(tmp_path), "PowerShell"),
        env=_clean_env(),
    )
    assert got["action"] == "deny"
    assert got["rule"] == "D1"
    assert "film_render" in got["reason"]


def test_denies_a_raw_fleet_shell():
    got = pf.decide(
        _payload("wsl -d awnix -u root -- nsenter -t 1 -m -- sh /mnt/c/tmp/fix.sh --apply"),
        env=_clean_env(),
    )
    assert got["action"] == "deny"
    assert got["rule"] == "D2"
    assert "fleet_control" in got["reason"]


def test_denies_a_hand_built_concat_and_names_the_media_lane(tmp_path):
    got = pf.decide(_payload("ffmpeg -f concat -safe 0 -i list.txt -c copy out.mp4",
                             str(tmp_path)), env=_clean_env())
    assert got["action"] == "deny"
    assert got["rule"] == "D4"
    assert "film_assemble" in got["reason"]
    assert pf.PRIORITY_SENTENCE[:40] in got["reason"]


def test_denies_generated_code_writing_outside_a_worktree(tmp_path):
    got = pf.decide(
        _payload("python - <<'PY'\nopen('place_stall_cars_v3c.json','w').write('[]')\nPY",
                 str(tmp_path)),
        env=_clean_env(),
    )
    assert got["action"] == "deny"
    assert got["rule"] == "D3"


def test_allows_the_read_only_list(tmp_path):
    for cmd in ("ls -la", "cat f", "grep -rn x .", "rg x", "git status --short",
                "gh pr view 123", "ffprobe -v error -show_streams in.mp4",
                "curl -s http://127.0.0.1:8200/ops", "awgit status"):
        assert pf.decide(_payload(cmd, str(tmp_path)), env=_clean_env())["action"] == "allow", cmd


def test_allows_a_deliverable_probe_and_an_analysis_heredoc(tmp_path):
    assert pf.decide(_payload("ffmpeg -i in.mp4 -f null -", str(tmp_path)),
                     env=_clean_env())["action"] == "allow"
    got = pf.decide(
        _payload("python - <<'PY'\nprint(sum(1 for l in open('x')))\nPY", str(tmp_path)),
        env=_clean_env(),
    )
    assert got["action"] == "allow"
    assert got["note"] is None


def test_escape_hatch_allows_once_and_logs_a_redacted_row(tmp_path):
    logdir = tmp_path / "pf-log"
    # longer than the 80-char head, so "never the whole command" is testable
    cmd = "ffmpeg -f concat -safe 0 -i " + " ".join(
        f"clips/take_{i:03d}.mov" for i in range(10)) + " -c copy out.mp4"
    assert len(cmd) > 80
    got = pf.decide(
        _payload(cmd, str(tmp_path)),
        env={"PATH": "", pf.BYPASS_ENV: "1", pf.LOG_DIR_ENV: str(logdir)},
    )
    assert got["action"] == "allow" and got["rule"] == "D4"
    rows = [json.loads(line) for f in logdir.glob("bypass-*.jsonl")
            for line in f.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["rule"] == "D4" and len(rows[0]["head"]) <= 80
    assert cmd not in json.dumps(rows[0])


def test_off_is_loud():
    got = pf.decide(_payload("ffmpeg -f concat -i l.txt -c copy out.mp4"),
                    env={"PATH": "", pf.OFF_ENV: "1"})
    assert got["action"] == "allow" and got["note"]


def test_fails_open_on_anything_it_does_not_understand():
    for payload in (None, "not a dict", {"tool_name": "Read", "tool_input": {"file_path": "x"}},
                    {"tool_name": "Bash", "tool_input": "ls"}, {"tool_name": "Bash"}):
        assert pf.decide(payload, env=_clean_env())["action"] == "allow"
    # and the hook entry itself: a malformed stream is exit 0, no output
    out, err = io.StringIO(), io.StringIO()
    assert pf.guard_main(stdin=io.StringIO("not json"), stdout=out, stderr=err) == 0
    assert out.getvalue() == ""


def test_json_deny_contract_is_what_the_harness_reads(tmp_path):
    # cwd with NO release lane, so D5 is the rule that fires
    out = io.StringIO()
    code = pf.guard_main(stdin=io.StringIO(json.dumps(
        _payload("gh release create v1.0.0 --repo x/y -n 'notes'", str(tmp_path)))),
        stdout=out, stderr=io.StringIO())
    body = json.loads(out.getvalue())
    assert code == 0
    assert body["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_declared_release_lane_is_allowed(tmp_path):
    """The rule refuses a RAW publish only where the repo declares no lane."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text("on: push\n")
    got = pf.decide(_payload("gh release create v1.0.0 --repo x/y -n 'notes'", str(tmp_path)),
                    env=_clean_env())
    assert got["action"] == "allow"


def test_exit2_contract_for_the_script_homes():
    err = io.StringIO()
    code = pf.guard_main(
        stdin=io.StringIO(json.dumps(_payload("rm -rf /c/Users/x/.aither/lock"))),
        stdout=io.StringIO(), stderr=err, mode="exit2",
    )
    assert code == 2 and "D7" in err.getvalue() and "lease release" in err.getvalue()


def test_the_shipped_copy_self_tests_clean():
    """The acceptance check, run against the shipped file rather than the source."""
    assert pf.self_test() == 0


def test_decide_stays_inside_its_latency_budget():
    """Median decide() over the whole fixture set. Budget 5 ms; this is pure regex."""
    import time
    payloads = [c["payload"] for c in pf.cases()]
    env = _clean_env()
    for p in payloads:
        pf.decide(p, env=env)
    samples = []
    for _ in range(300):
        for p in payloads:
            t0 = time.perf_counter()
            pf.decide(p, env=env)
            samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    assert samples[len(samples) // 2] < 5.0
