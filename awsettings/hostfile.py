"""One opaque file, one copy per host: the ``aitherzero`` domain's engine.

Every other domain is a JSON object merged key by key. AitherZero's
``config.local.psd1`` is PowerShell data, and parsing it here would mean a second
reader of a format this package does not own -- one that disagrees with the real
reader exactly when it matters. So the file travels as TEXT, byte-for-byte, and is
kept per HOST rather than merged: the question this domain answers is "this machine
died; put its overrides on the new one", not "reconcile two machines' edits".

Remote shape, under the domain's namespace::

    {"version": 1,
     "hosts": {"<hostname>": {"text": "...", "sha256": "...", "bytes": N,
                              "pushed_at": "<UTC ISO>", "path": "<where it lived>"}}}

WHY A SECRET SCAN, NOT A REDACT. A redact strips keys by NAME from an object. Opaque
text has no keys this package may trust, so the guard is coarser and louder: a line
that looks like a credential refuses the WHOLE file, names the rule and the line,
and never prints the value. Same guarantee in both directions -- a pull refuses a
secret-shaped copy as well, so the hub cannot be used to plant one.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import socket
from pathlib import Path
from typing import Any

from .store import CouldNotRunError

#: Env override for this machine's name, for tests and for a host whose name moved.
HOST_ENV = "AWSETTINGS_HOST"

#: Credential VALUES, wherever they sit on a line.
_VALUE_RULES: tuple = (
    ("sk-", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}")),
    ("gh*_ token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("github_pat_", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("AKIA", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("xox*- (slack)", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("*_live_ (stripe)", re.compile(r"\b(?:pk|sk|rk)_live_[A-Za-z0-9]{10,}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("token= in a url", re.compile(
        r"(?i)[?&](?:access_?token|token|api_?key|apikey|key|secret)=[^&\s'\"]{8,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)

#: ``Name = value`` where the NAME ends in a credential word. ``MaxTokens``,
#: ``TokenFile`` and ``RequirePassword`` do not match: the word must end the name.
_KEY_RULE = re.compile(
    r"""(?:^|[\s;{(,])['"]?(?P<key>[A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|"""
    r"""token|api[_-]?key|access[_-]?key|bearer|credential)s?)['"]?\s*=\s*"""
    r"""(?P<val>'[^']*'|"[^"]*"|[^\s;})#]*)""",
    re.IGNORECASE)

#: Values that name no secret: empty, a variable or env reference, a boolean, a
#: container, a number.
_HARMLESS_VALUE = re.compile(
    r"""^(?:''|""|\$\S*|@[({].*|-?\d+(?:\.\d+)?|)$""")


def secret_findings(text: str) -> list[str]:
    """Every credential-shaped line in ``text`` as ``line N: <rule> (<key>)``.

    Never returns the value: the finding is printed, and printing the secret while
    refusing to send it would leak it into a terminal log instead.
    """
    out: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            # A comment may MENTION a password; only a value can be one. Value
            # rules still run on it below -- a pasted key in a comment is a key.
            pass
        else:
            hit = next((m for m in _KEY_RULE.finditer(line)
                        if not _HARMLESS_VALUE.match(m.group("val"))), None)
            if hit:
                out.append(f"line {n}: credential-named key ({hit.group('key')})")
                continue
        for name, rx in _VALUE_RULES:
            if rx.search(line):
                out.append(f"line {n}: {name}")
                break
    return out


def this_host() -> str:
    return (os.environ.get(HOST_ENV) or "").strip() or socket.gethostname()


def _find_host(hosts: dict, name: str) -> str | None:
    """Host names compare case-insensitively: Windows upper-cases them, other
    systems do not, and one machine must not end up with two copies."""
    want = name.lower()
    for key in hosts:
        if str(key).lower() == want:
            return str(key)
    return None


def read_text(path: Path) -> str | None:
    """The file as text, byte-exact on the way back (CRLF and a BOM survive).
    None when absent; a file that is not UTF-8 is could-not-judge, never guessed."""
    if not path.is_file():
        return None
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CouldNotRunError(
            f"{path} is not UTF-8 ({exc.reason}); re-save it as UTF-8 to sync it") from exc


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hosts(remote: dict) -> dict:
    hosts = remote.get("hosts", {}) if isinstance(remote, dict) else {}
    return hosts if isinstance(hosts, dict) else {}


def backup_dir() -> Path:
    """Outside the repo on purpose: the file's own directory is NOT gitignored for
    a ``.bak``, and a backup of a per-machine file must never ride a commit."""
    from . import config
    return config.home() / "backups" / "aitherzero"


def _backup(target: Path, text: str) -> Path:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = backup_dir() / f"{target.name}.{stamp}.bak"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(text.encode("utf-8"))
    return dest


def _write_atomic(target: Path, text: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_bytes(text.encode("utf-8"))
    os.replace(tmp, target)


def _entry_problem(entry: Any) -> str | None:
    """Why an arriving copy may not be written, or None when it may."""
    if not isinstance(entry, dict) or not isinstance(entry.get("text"), str):
        return "the stored copy has no text"
    if entry.get("sha256") != _sha(entry["text"]):
        return "the stored copy does not match its own sha256 (truncated or edited)"
    found = secret_findings(entry["text"])
    if found:
        return "the stored copy is secret-shaped: " + "; ".join(found)
    return None


# --- commands ---------------------------------------------------------------


def cmd_status(args, dom, backend, target: Path) -> int:
    local = read_text(target)
    try:
        remote = backend.get()
    except CouldNotRunError as exc:
        print(f"local:  {target}")
        print(f"remote: {backend.describe()}")
        print(f"DEAD: {exc}")
        return 2
    me = this_host()
    hosts = _hosts(remote)
    print(f"domain: {dom.name} -- {dom.summary}")
    print(f"local:  {target} ({'present' if local is not None else 'absent'})")
    print(f"remote: {backend.describe()}")
    print(f"host:   {me}")
    if not hosts:
        print("no host has pushed a copy yet")
        return 0
    print(f"{len(hosts)} host(s) have a copy:")
    for name in sorted(hosts, key=str.lower):
        e = hosts[name] if isinstance(hosts[name], dict) else {}
        mark = ""
        if name.lower() == me.lower():
            if local is None:
                mark = "  <- this host; local file absent"
            elif e.get("sha256") == _sha(local):
                mark = "  <- this host; in step"
            else:
                mark = "  <- this host; local differs (push to update)"
        print(f"  {name:<20} {e.get('pushed_at', '?')}  {e.get('bytes', '?')} bytes  "
              f"sha256 {str(e.get('sha256', '?'))[:12]}{mark}")
    return 0


def cmd_get(args, dom, backend, target: Path) -> int:
    """The per-host METADATA as JSON; never the file text (that is what pull is for)."""
    try:
        remote = backend.get()
    except CouldNotRunError as exc:
        print(f"DEAD: {exc}")
        return 2
    rows = {name: {k: v for k, v in (e or {}).items() if k != "text"}
            for name, e in _hosts(remote).items() if isinstance(e, dict)}
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def cmd_push(args, dom, backend, target: Path) -> int:
    local = read_text(target)
    if local is None:
        print(f"DEAD: {target} does not exist; nothing to push")
        return 2
    found = secret_findings(local)
    if found:
        # Printed even under --quiet: a refused push must never look like a no-op.
        print(f"REFUSED: {target} looks like it holds a credential; not pushed")
        for f in found:
            print(f"  {f}")
        return 1
    try:
        remote = backend.get()
    except CouldNotRunError as exc:
        if not args.quiet:
            print(f"DEAD: {exc}")
        return 2
    me = this_host()
    hosts = dict(_hosts(remote))
    key = _find_host(hosts, me) or me
    digest = _sha(local)
    if isinstance(hosts.get(key), dict) and hosts[key].get("sha256") == digest:
        if not args.quiet:
            print(f"already in step: {key} copy on {backend.describe()} matches {target}")
        return 0
    hosts[key] = {
        "text": local, "sha256": digest, "bytes": len(local.encode("utf-8")),
        "pushed_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "path": str(target),
    }
    snapshot: dict[str, Any] = {"version": 1, "hosts": hosts}
    from . import config as _config
    if getattr(args, "sign", False) or _config.flag("AWSETTINGS_SIGN"):
        from .trust import UntrustedProfileError, seal
        try:
            snapshot = seal(snapshot)
        except UntrustedProfileError as exc:
            print(f"REFUSED: {exc}")
            return 1
    if args.dry_run:
        meta = {k: v for k, v in hosts[key].items() if k != "text"}
        print(f"would push {key}: " + json.dumps(meta))
        return 0
    from .profile import ProfileRejectedError
    try:
        backend.put(snapshot)
    except CouldNotRunError as exc:
        if not args.quiet:
            print(f"DEAD: {exc}")
        return 2
    except ProfileRejectedError as exc:
        print(f"REFUSED: {exc}")
        for path in exc.dropped:
            print(f"  dropped: {path}")
        return 1
    if not args.quiet:
        print(f"pushed {target.name} as host {key!r} ({hosts[key]['bytes']} bytes, "
              f"sha256 {digest[:12]}) to {backend.describe()}")
    return 0


def cmd_pull(args, dom, backend, target: Path) -> int:
    try:
        remote = backend.get()
        local = read_text(target)
    except CouldNotRunError as exc:
        if not args.quiet:
            print(f"DEAD: {exc}")
        return 2
    hosts = _hosts(remote)
    want = (getattr(args, "host", None) or "").strip() or this_host()
    key = _find_host(hosts, want)
    if key is None:
        print(f"REFUSED: no copy for host {want!r}; hosts with a copy: "
              f"{', '.join(sorted(hosts)) or 'none'}")
        return 1
    problem = _entry_problem(hosts[key])
    if problem:
        print(f"REFUSED: host {key!r}: {problem}")
        return 1
    text = hosts[key]["text"]
    if local == text:
        if not args.quiet:
            print(f"already in step: {target} matches host {key!r}")
        return 0
    if args.dry_run:
        state = "absent" if local is None else f"{len(local.splitlines())} lines"
        print(f"would write host {key!r} copy ({len(text.splitlines())} lines, pushed "
              f"{hosts[key].get('pushed_at', '?')}) to {target} (now {state})")
        return 0
    saved = _backup(target, local) if local is not None else None
    _write_atomic(target, text)
    if not args.quiet:
        print(f"restored host {key!r} copy (pushed {hosts[key].get('pushed_at', '?')}) "
              f"to {target}")
        if saved:
            print(f"  previous file backed up to {saved}")
    return 0


def self_test_problems() -> list[str]:
    """The arms that can do harm, offline. Returned for cli.self_test to report."""
    problems: list[str] = []
    planted = "@{\n  ApiKey = 'abc123def456'\n}\n"
    if not any("ApiKey" in f for f in secret_findings(planted)):
        problems.append("aitherzero: a credential-named key with a value was not caught")
    if "abc123def456" in " ".join(secret_findings(planted)):
        problems.append("aitherzero: a secret finding printed the secret's value")
    if not secret_findings("# note: sk-" + "a" * 24 + "\n"):
        problems.append("aitherzero: a pasted sk- key in a comment was not caught")
    benign = ("@{\n  Token = ''\n  Password = $null\n  MaxTokens = 4096\n"
              "  TokenFile = 'C:/x/token.txt'\n  RequirePassword = $true\n"
              "  # set your password in the vault\n}\n")
    if secret_findings(benign):
        problems.append("aitherzero: benign lines were refused: "
                        + "; ".join(secret_findings(benign)))
    if _entry_problem({"text": planted, "sha256": _sha(planted)}) is None:
        problems.append("aitherzero: a secret-shaped copy could ARRIVE on pull")
    if _entry_problem({"text": "x", "sha256": "0"}) is None:
        problems.append("aitherzero: a copy that fails its own sha256 was accepted")
    return problems
