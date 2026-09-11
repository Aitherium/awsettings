"""awsettings — your agent's permissions and config, following you to the next machine.

    awsettings status                 what is here, what is remote, what differs
    awsettings pull                   remote -> local (union; never drops a deny)
    awsettings push                   local  -> remote (credentials stripped)
    awsettings hook install           run it automatically from now on
    awsettings hook uninstall
    awsettings backends               which model backends this box can launch
    awsettings backends --probe       ...and which of them will actually answer
    awsettings preflight <profile>    can a session launch on this one? 0 yes 1 no 2 unsure
    awsettings --self-test

Exit **0** did the thing · **1** a rule refused it · **2** could not judge — the
profile was unreachable, or a settings file would not parse. Never 0 for "I could
not look": a sync that silently did nothing and one that had nothing to do are
the same green run otherwise, and telling them apart is the whole point.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .backends import CouldNotJudgeError as BackendsCouldNotJudgeError
from .backends import ProbeVerdict as BackendProbeVerdict
from .backends import discover as discover_backends
from .backends import load_profiles_for_probe, vault_lookup
from .backends import probe as probe_backend
from .backends import probe_self_test as backends_probe_self_test
from .backends import self_test as backends_self_test
from .core import SECRET_KEYS, diff_summary, merge, redact
from .hooks import install_to, installed, uninstall_from
from .profile import resolve
from .store import CouldNotRunError, local_settings_path, read_json, write_json
from .trust import UntrustedProfileError

DEBOUNCE_STAMP = Path.home() / ".awsettings" / "last-push"
DEBOUNCE_SECONDS = 5.0


def _root(args) -> Path | None:
    if args.user:
        return None
    return Path(args.root or os.getcwd())


def cmd_status(args) -> int:
    target = local_settings_path(_root(args))
    backend = resolve(args.url, args.profile)
    local = read_json(target)
    try:
        remote = backend.get()
    except CouldNotRunError as exc:
        print(f"local:  {target}")
        print(f"remote: {backend.describe()}")
        print(f"DEAD: {exc}")
        return 2
    merged = merge(local, remote)
    lines = diff_summary(local, merged)
    print(f"local:  {target} ({'present' if target.is_file() else 'absent'})")
    print(f"remote: {backend.describe()}")
    print(f"hooks:  {', '.join(installed(local)) or 'not installed'}")
    if not lines:
        print("in step: a pull would change nothing")
        return 0
    print(f"a pull would apply {len(lines)} change(s):")
    for ln in lines:
        print("  " + ln)
    return 0


def cmd_pull(args) -> int:
    target = local_settings_path(_root(args))
    backend = resolve(args.url, args.profile)
    try:
        local = read_json(target)
        remote = backend.get()
    except CouldNotRunError as exc:
        # Offline is the normal state of a laptop. Say so and keep the local file.
        if not args.quiet:
            print(f"DEAD: {exc}")
        return 2
    merged = merge(local, remote, prune_denies=args.prune_denies)
    lines = diff_summary(local, merged)
    if not lines:
        if not args.quiet:
            print("already in step")
        return 0
    if args.dry_run:
        print(f"would apply {len(lines)} change(s) to {target}:")
        for ln in lines:
            print("  " + ln)
        return 0
    write_json(target, merged)
    if not args.quiet:
        print(f"applied {len(lines)} change(s) to {target}:")
        for ln in lines:
            print("  " + ln)
    return 0


def cmd_push(args) -> int:
    if args.debounce:
        try:
            last = DEBOUNCE_STAMP.stat().st_mtime
            if time.time() - last < DEBOUNCE_SECONDS:
                return 0
        except OSError:
            pass
    target = local_settings_path(_root(args))
    backend = resolve(args.url, args.profile)
    try:
        local = read_json(target)
    except CouldNotRunError as exc:
        if not args.quiet:
            print(f"DEAD: {exc}")
        return 2
    snapshot = redact(local)
    if args.dry_run:
        print(json.dumps(snapshot, indent=2))
        return 0
    try:
        backend.put(snapshot)
    except CouldNotRunError as exc:
        if not args.quiet:
            print(f"DEAD: {exc}")
        return 2
    DEBOUNCE_STAMP.parent.mkdir(parents=True, exist_ok=True)
    DEBOUNCE_STAMP.write_text(str(time.time()), encoding="utf-8")
    if not args.quiet:
        kept = sorted(snapshot)
        dropped = sorted(k for k in local if k not in snapshot)
        print(f"pushed {len(kept)} key(s) to {backend.describe()}")
        if kept:
            print("  sent:    " + ", ".join(kept))
        if dropped:
            print("  kept local: " + ", ".join(dropped))
    return 0


def cmd_backends(args) -> int:
    """Report which model backends this machine can launch a session on.

    READ-ONLY, and deliberately so. A backend override is session-scoped by
    design: it lives in the environment of the process being launched and
    nowhere else. This command therefore prints how to launch and changes
    nothing -- `awsettings` syncs profile DEFINITIONS between machines, never an
    active override, and conflating the two is how a backend outlives the
    session that wanted it.
    """
    try:
        found = discover_backends()
    except BackendsCouldNotJudgeError as exc:
        # A present-but-unreadable profile file is not an empty roster.
        print(f"DEAD: {exc}")
        return 2

    probes: dict = {}
    if args.probe:
        # LAUNCHABLE and WORKING are different questions and the second one costs
        # a request, so it is opt-in. Without it this command would either be slow
        # for callers that only want the roster, or would answer the easy question
        # while looking like it answered the hard one.
        profiles = load_profiles_for_probe()
        for backend in found:
            if not backend.launchable:
                continue
            if not backend.base_url or not backend.model:
                # The harness default authenticates through its own sign-in,
                # which nothing here can see. Probing it can only ever return
                # UNKNOWN, and reporting that as DEAD would make this command
                # exit non-zero on every healthy machine -- an always-red check
                # is one people stop reading, which is how the real failures get
                # missed. Not probeable is a different statement from broken.
                continue
            token = vault_lookup(backend, profiles)
            probes[backend.id] = probe_backend(
                backend, token=token, use_cache=not args.no_cache
            )

    if args.json:
        rows = []
        for backend in found:
            row = backend.as_dict()
            hit = probes.get(backend.id)
            if hit is not None:
                row["probe"] = hit.as_dict()
            rows.append(row)
        print(json.dumps(rows, indent=2))
        return 0

    print(f"Backends this machine can launch ({len(found)}):")
    for backend in found:
        mark = "  " if backend.launchable else "! "
        launcher = backend.launcher or "-"
        model = backend.model or "(the account you are signed in as)"
        line = f"{mark}{backend.id:22} {launcher:10} {model}"
        hit = probes.get(backend.id)
        if hit is not None:
            flag = "ok" if hit.usable else "DEAD"
            line += f"   [{flag}: {hit.verdict.value}"
            line += f", {hit.latency_ms}ms]" if hit.latency_ms else "]"
        elif args.probe and backend.launchable:
            line += "   [not probeable: its own sign-in]"
        print(line)
        if backend.hint:
            print(f"    {backend.hint}")
        if hit is not None and hit.detail:
            print(f"    {hit.detail}")

    unlaunchable = [b for b in found if not b.launchable]
    if unlaunchable:
        print()
        print(f"  ! {len(unlaunchable)} configured but not launchable from here")
    if probes:
        dead = [i for i, pr in probes.items() if not pr.usable]
        if dead:
            print()
            print(f"  ! probed DEAD: {', '.join(sorted(dead))}")
            # Exit 1, not 0. A roster listing a backend that cannot answer is the
            # exact state this command exists to surface, and a caller scripting
            # a preflight needs a non-zero to act on.
            return 1
    return 0


def cmd_preflight(args) -> int:
    """Can a session launch on ONE named backend and answer a turn?

    Built for a LAUNCHER to call, which shapes everything about it: one line of
    output, and an exit code a shell can branch on.

        0  usable -- go
        1  definitively not usable, and the reason is on stdout
        2  could not judge

    Exit 2 is separate from exit 1 on purpose. A launcher must not fall back to
    another backend because a probe timed out; that would move a user off the
    model they asked for on the strength of a flaky network. Only a definite
    verdict earns a fallback.

    $AWSETTINGS_PROBE_TOKEN short-circuits the key lookup, so a switcher that has
    already resolved the credential does not pay for a second vault round trip.
    """
    profiles = load_profiles_for_probe()
    try:
        found = discover_backends()
    except BackendsCouldNotJudgeError as exc:
        print(f"could not judge: {exc}")
        return 2

    wanted = args.profile
    match = [b for b in found if b.id == wanted] or [b for b in found if b.launcher == wanted]
    if not match:
        print(f"could not judge: no backend named '{wanted}' on this machine")
        return 2
    backend = match[0]

    if not backend.base_url or not backend.model:
        # The harness default. Nothing here can see its sign-in, and a launcher
        # asking about it should proceed rather than be blocked by a probe that
        # is structurally unable to answer.
        print(f"{backend.id}: the harness default; its own sign-in decides, not this check")
        return 0

    token = os.environ.get("AWSETTINGS_PROBE_TOKEN") or vault_lookup(backend, profiles)
    hit = probe_backend(backend, token=token, use_cache=not args.no_cache)
    suffix = f" ({hit.detail})" if hit.detail else ""
    cached = " [cached]" if hit.cached else ""
    if hit.usable:
        print(f"{backend.id}: {hit.verdict.value}{suffix}{cached}")
        return 0
    if hit.verdict is BackendProbeVerdict.UNKNOWN:
        print(f"{backend.id}: could not judge -- {hit.verdict.value}{suffix}{cached}")
        return 2
    print(f"{backend.id}: {hit.verdict.value}{suffix}{cached}")
    return 1


def cmd_hook(args) -> int:
    target = local_settings_path(_root(args))
    if args.action == "install":
        path, evs = install_to(target)
        print(f"installed into {path}: {', '.join(evs) or 'nothing'}")
        print("  SessionStart -> pull   (a new machine is stale before its first tool call)")
        print("  PostToolUse  -> push   (debounced; a rule you approve here is on its way)")
        return 0
    path, evs = uninstall_from(target)
    print(f"removed from {path}; still installed: {', '.join(evs) or 'nothing'}")
    return 0


def self_test() -> int:
    """Offline proof of the properties that can do harm. No network, no profile."""
    import tempfile
    problems: list[str] = []

    # --- redaction: by NAME, not by shape --------------------------------
    src = {
        "env": {"OPENAI_API_KEY": "sk-real"},
        "apiKeyHelper": "/bin/print-my-token",
        "sandbox": {"enabled": True, "credentials": {"envVars": [{"name": "X"}]}},
        "permissions": {"allow": ["Bash(git *)"]},
        "someLocalExperiment": 1,
    }
    red = redact(src)
    for k in ("env", "apiKeyHelper"):
        if k in red:
            problems.append(f"redact() let the credential key {k!r} through")
    # Both halves, because the first alone passes VACUOUSLY when `sandbox` is not
    # synced at all — which is exactly the state this shipped in, making the guard
    # unreachable while its check stayed green.
    if "sandbox" not in red:
        problems.append("redact() dropped `sandbox` entirely, so the credential-subkey "
                        "guard is unreachable — a protection nothing can run")
    elif "credentials" in red["sandbox"]:
        problems.append("redact() left sandbox.credentials in the snapshot")
    elif red["sandbox"].get("enabled") is not True:
        problems.append("redact() stripped more of `sandbox` than the credentials")
    if "someLocalExperiment" in red:
        problems.append("redact() pushed an unknown local key instead of leaving it home")
    if src["env"]["OPENAI_API_KEY"] != "sk-real":
        problems.append("redact() MUTATED its input")

    # --- merge: union, not replace ---------------------------------------
    local = {"permissions": {"allow": ["Bash(local *)"], "deny": ["Bash(rm -rf *)"]},
             "enabledMcpjsonServers": ["aitheros"], "env": {"S": "keep"}}
    remote = {"permissions": {"allow": ["Bash(portal *)"]},
              "enabledMcpjsonServers": ["awsh"]}
    m = merge(local, remote)
    if sorted(m["permissions"]["allow"]) != ["Bash(local *)", "Bash(portal *)"]:
        problems.append("merge() did not UNION allow rules — a device silently loses "
                        "the rule the other one never had")
    if m["permissions"]["deny"] != ["Bash(rm -rf *)"]:
        problems.append("merge() dropped a local deny the remote did not carry")
    if sorted(m["enabledMcpjsonServers"]) != ["aitheros", "awsh"]:
        problems.append("merge() did not union enabledMcpjsonServers")
    if m.get("env", {}).get("S") != "keep":
        problems.append("merge() lost a device-local secret it must never touch")
    if local["permissions"]["allow"] != ["Bash(local *)"]:
        problems.append("merge() MUTATED its local input")

    # --- a profile may not push credentials DOWN --------------------------
    if merge({}, {"env": {"X": "y"}}).get("env") is not None:
        problems.append("merge() accepted an env block pushed from the profile — a "
                        "settings profile is not a secret channel")

    # --- deny is one-way unless explicitly pruned -------------------------
    if merge({"permissions": {"deny": ["Bash(curl *)"]}},
             {"permissions": {"deny": []}})["permissions"]["deny"] != ["Bash(curl *)"]:
        problems.append("a deny was dropped by a default sync — the one direction this "
                        "must never go")
    if merge({"permissions": {"deny": ["Bash(curl *)"]}}, {"permissions": {"deny": []}},
             prune_denies=True)["permissions"]["deny"] != []:
        problems.append("prune_denies=True did not prune")

    # --- hooks are idempotent --------------------------------------------
    from .hooks import plan
    once = plan({})
    twice = plan(once)
    n = len(twice["hooks"]["SessionStart"])
    if n != 1:
        problems.append(f"installing twice left {n} SessionStart hooks — a hook that "
                        f"accumulates runs N times per event")
    if plan({"hooks": {"SessionStart": [{"matcher": "", "hooks": [
            {"type": "command", "command": "somebody-elses-hook"}]}]}
            })["hooks"]["SessionStart"].__len__() != 2:
        problems.append("install clobbered somebody else's hook instead of adding to it")
    from .hooks import uninstall as hk_uninstall
    if installed(hk_uninstall(twice)):
        problems.append("uninstall left one of our hooks behind")

    # --- a malformed settings file RAISES, never reads as empty -----------
    with tempfile.TemporaryDirectory() as td:
        bad = Path(td) / "settings.local.json"
        bad.write_text("{ not json", encoding="utf-8")
        try:
            read_json(bad)
            problems.append("a malformed settings file read as EMPTY — that is how a "
                            "sync overwrites a half-finished edit")
        except CouldNotRunError:
            pass
        # ...and a write is atomic: no .tmp left behind.
        good = Path(td) / "out.json"
        write_json(good, {"a": 1})
        if list(Path(td).glob("*.tmp")):
            problems.append("write_json left a .tmp file behind")
        if json.loads(good.read_text(encoding="utf-8")) != {"a": 1}:
            problems.append("write_json did not write what it was given")

    # --- the write target is the personal file ---------------------------
    with tempfile.TemporaryDirectory() as td:
        if local_settings_path(Path(td)).name != "settings.local.json":
            problems.append("the write target is not settings.local.json — syncing into "
                            "the committed settings.json hands the whole team one "
                            "person's permission rules")

    # --- the secret list is not empty ------------------------------------
    if not SECRET_KEYS:
        problems.append("the credential denylist is empty, so redact() is a no-op")

    if problems:
        print("SELF-TEST FAILED:")
        for p in problems:
            print("  x " + p)
        return 1
    # The backend resolver has its own arms; run them here so one --self-test is
    # the whole package's verdict. A second entry point nobody remembers to call
    # is a test that does not run.
    if backends_self_test() != 0:
        return 1
    if backends_probe_self_test() != 0:
        return 1

    print("self-test ok: credentials never leave or arrive, arrays union instead of "
          "replacing, a deny is never dropped by default, hooks install once and do not "
          "clobber, a malformed file refuses rather than reading empty, writes are "
          "atomic, the target is the personal settings file, the backend roster "
          "reads a quoted shim, hides a documentation key, and marks a profile with no "
          "launcher unlaunchable instead of dropping it, and a probe tells an empty "
          "balance apart from a bad key apart from an unknown model instead of "
          "reporting one boolean")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="awsettings",
                                 description=__doc__.splitlines()[0])
    ap.add_argument("--version", action="version", version=f"awsettings {__version__}")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--root", help="project root (default: cwd)")
    ap.add_argument("--user", action="store_true",
                    help="act on the user-level settings instead of a project's")
    ap.add_argument("--url", help="profile endpoint (default: $AWSETTINGS_URL)")
    ap.add_argument("--profile", help="profile FILE (default: $AWSETTINGS_PROFILE)")
    ap.add_argument("--quiet", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("status")
    p = sub.add_parser("pull")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--prune-denies", action="store_true",
                   help="allow the profile to REMOVE deny/ask rules (off by default: a "
                        "lost deny costs the thing it prevented)")
    p = sub.add_parser("push")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debounce", action="store_true")
    p = sub.add_parser("hook")
    p.add_argument("action", choices=["install", "uninstall"])
    p = sub.add_parser("preflight")
    p.add_argument("profile", help="profile id or launcher name (e.g. deepseek, cds)")
    p.add_argument("--no-cache", action="store_true",
                   help="ignore the 15-minute probe cache and ask the endpoint again")
    p = sub.add_parser("backends")
    p.add_argument("--json", action="store_true",
                   help="machine-readable roster, for a picker in another surface")
    p.add_argument("--probe", action="store_true",
                   help="also send one minimal request per backend and classify the "
                        "result (key present? credit left? model known?). Exits 1 if "
                        "any launchable backend cannot answer.")
    p.add_argument("--no-cache", action="store_true",
                   help="ignore the 15-minute probe cache and ask the endpoint again")

    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    for name in ("dry_run", "prune_denies", "debounce", "json", "probe", "no_cache"):
        if not hasattr(args, name):
            setattr(args, name, False)

    try:
        if args.cmd == "status":
            return cmd_status(args)
        if args.cmd == "pull":
            return cmd_pull(args)
        if args.cmd == "push":
            return cmd_push(args)
        if args.cmd == "hook":
            return cmd_hook(args)
        if args.cmd == "backends":
            return cmd_backends(args)
        if args.cmd == "preflight":
            return cmd_preflight(args)
    except UntrustedProfileError as exc:
        # A profile that cannot be proven yours is REFUSED, and the settings
        # are not applied. This is the one failure that must never be quiet.
        print(f"REFUSED: {exc}")
        return 2
    except CouldNotRunError as exc:
        print(f"DEAD: {exc}")
        return 2
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
