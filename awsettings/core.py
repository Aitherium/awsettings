"""The merge and the redaction. Pure, offline, and the only place harm can happen.

Everything in this module is a function of its arguments. That is deliberate: the
two operations that can hurt you — sending a credential somewhere, and losing a
rule you were relying on — need no network to test, so they are tested without
one.

THE THREE RULES, each already paid for:

1. **Credentials never travel, and are dropped by NAME.** Not by inspecting the
   value. A "does this look like a token" heuristic passes every secret that does
   not look like one, and that failure is invisible until the secret is already
   published. A name-based denylist is auditable; a shape-based one is a hope.

2. **Arrays UNION; they are never replaced.** A settings file is edited from more
   than one place, so replace semantics means device B silently loses the rule
   device A never had. This is not hypothetical: it is what happens to a shared
   config any time one writer's copy is stamped over another's.

3. **A deny is ONE-WAY.** A sync may ADD a deny or ask rule; it may never drop
   one. A lost allow rule costs a prompt. A lost deny rule costs the thing the
   deny existed to prevent — silently, on a machine whose owner still believes it
   is there. `prune_denies` exists for the deliberate case and is never a default.
"""
from __future__ import annotations

import copy
import json
from typing import Any

#: Array-valued keys that MERGE as a union rather than replacing (rule 2).
UNION_ARRAYS: tuple[tuple[str, ...], ...] = (
    ("permissions", "allow"),
    ("permissions", "deny"),
    ("permissions", "ask"),
    ("permissions", "additionalDirectories"),
    ("enabledMcpjsonServers",),
    ("disabledMcpjsonServers",),
)

#: Keys whose VALUES are credentials, or commands that fetch one. Dropped whole
#: from anything that leaves this machine, and refused on anything arriving.
SECRET_KEYS = frozenset({
    "env",                    # arbitrary values, routinely tokens
    "apiKeyHelper",
    "proxyAuthHelper",
    "awsCredentialExport",
    "awsAuthRefresh",
    "gcpAuthRefresh",
    "otelHeadersHelper",
    "policyHelper",
})

#: Sub-objects that hold credential material inside an otherwise-syncable key.
SECRET_SUBKEYS: dict[str, frozenset[str]] = {
    "sandbox": frozenset({"credentials"}),
}

#: What is worth syncing. An unknown key is left at home rather than guessed at:
#: it is far more likely a local experiment than a preference somebody wants
#: pushed to every machine they own.
SYNCED_KEYS = frozenset({
    "permissions",
    # `sandbox` carries the network allowlist and filesystem rules, which are
    # exactly the kind of thing you want on every machine — and `sandbox.credentials`,
    # which is exactly what must not travel. That pairing is why SECRET_SUBKEYS
    # exists at all; leaving `sandbox` out of this set made that guard UNREACHABLE,
    # i.e. deleted code wearing the shape of a protection. Caught by a test that
    # asserted the strip, not by reading it.
    "sandbox",
    "enabledMcpjsonServers",
    "disabledMcpjsonServers",
    "enableAllProjectMcpServers",
    "hooks",
    "outputStyle",
    "statusLine",
    "alwaysThinkingEnabled",
    "autoCompactEnabled",
    "spinnerTipsEnabled",
    "todoFeatureEnabled",
    "attribution",
})


def _domain(domain: Any) -> Any:
    """The domain in force. ``None`` is the original single-file behaviour, so every
    caller written before domains existed keeps exactly what it had."""
    if domain is not None:
        return domain
    from .domains import get_domain
    return get_domain("claude")


def redact(settings: dict[str, Any], *, domain: Any = None) -> dict[str, Any]:
    """The snapshot that may leave this machine. Never mutates the input."""
    dom = _domain(domain)
    out: dict[str, Any] = {}
    for k, v in settings.items():
        if k in dom.secret_keys or k not in dom.synced_keys:
            continue
        if k in dom.home_subkeys and isinstance(v, dict):
            v = {sk: sv for sk, sv in v.items() if sk not in dom.home_subkeys[k]}
        out[k] = copy.deepcopy(v)
    return out


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    """``src`` over ``dst``, leaf by leaf. Only objects recurse; a scalar or an array
    from ``src`` replaces. An explicit ``None`` is KEPT, not skipped: it is how a
    field is un-set on every machine, since a merge cannot otherwise carry a delete."""
    out = dict(dst)
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _get(d: dict[str, Any], path: tuple[str, ...]) -> Any:
    cur: Any = d
    for seg in path:
        if not isinstance(cur, dict) or seg not in cur:
            return None
        cur = cur[seg]
    return cur


def _set(d: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cur = d
    for seg in path[:-1]:
        nxt = cur.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    cur[path[-1]] = value


def merge(local: dict[str, Any], remote: dict[str, Any], *,
          prune_denies: bool = False, domain: Any = None) -> dict[str, Any]:
    """Remote over local, UNION on the array keys, credentials untouched.

    Neither input is mutated. A credential block arriving from the remote is
    REFUSED — a settings profile is not a secret channel, and a client that
    accepts one becomes a way to push an `apiKeyHelper` at somebody.

    That refusal covers the NESTED stay-home keys too. It did not always: the
    top-level denylist was checked on arrival and the sub-key one was checked only
    on the way OUT, so a profile carrying `sandbox.credentials` was merged straight
    into the local file. Anyone able to write the profile could plant a credential
    block on every machine that pulled it. `redact()` stripping a key is not the
    same guarantee as `merge()` refusing it, and only one of them was tested.
    """
    dom = _domain(domain)
    out = copy.deepcopy(local)

    for k, v in remote.items():
        if k in dom.secret_keys:
            continue
        if dom.strict_inbound and k not in dom.synced_keys:
            continue
        if k in dom.home_subkeys and isinstance(v, dict):
            v = {sk: sv for sk, sv in v.items() if sk not in dom.home_subkeys[k]}
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            if dom.deep:
                out[k] = _deep_merge(out[k], v)
            else:
                merged = dict(out[k])
                merged.update(v)
                out[k] = merged
        else:
            out[k] = copy.deepcopy(v)

    for path in dom.union_arrays:
        lv, rv = _get(local, path), _get(remote, path)
        if lv is None and rv is None:
            continue
        lv = lv if isinstance(lv, list) else []
        rv = rv if isinstance(rv, list) else []
        if prune_denies and path[-1] in dom.one_way:
            union = list(rv)
        else:
            union = list(lv)
            union += [x for x in rv if x not in union]
        _set(out, path, union)

    # Device-local secrets survive verbatim. Stated explicitly rather than left
    # to fall out of the loop above, because "preserved by omission" is exactly
    # the kind of property a later refactor removes without noticing.
    for k in dom.secret_keys:
        if k in local:
            out[k] = copy.deepcopy(local[k])
    return out


def _leaf_changes(before: Any, after: Any, prefix: str, lines: list[str]) -> None:
    """Name every leaf that moved. For a deep domain "~ actors" is not an answer:
    the whole point of a per-field config is knowing WHICH field a pull touched."""
    if isinstance(before, dict) and isinstance(after, dict):
        for k in sorted(set(before) | set(after)):
            path = f"{prefix}.{k}" if prefix else str(k)
            if k not in before:
                lines.append(f"+ {path} = {_short(after[k])}")
            elif k not in after:
                lines.append(f"- {path}")
            else:
                _leaf_changes(before[k], after[k], path, lines)
    elif before != after:
        lines.append(f"~ {prefix}: {_short(before)} -> {_short(after)}")


def _short(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= 60 else text[:57] + "..."


def diff_summary(before: dict[str, Any], after: dict[str, Any], *,
                 domain: Any = None) -> list[str]:
    """Human-readable list of what a merge actually changed.

    A sync that reports "ok" and cannot say what it did is indistinguishable
    from one that did nothing, which is how drift goes unnoticed for months.
    """
    dom = _domain(domain)
    lines: list[str] = []
    if dom.deep:
        _leaf_changes(
            {k: v for k, v in before.items() if k not in dom.secret_keys},
            {k: v for k, v in after.items() if k not in dom.secret_keys},
            "", lines)
        return lines
    for path in UNION_ARRAYS:
        b = _get(before, path) or []
        a = _get(after, path) or []
        added = [x for x in a if x not in b]
        removed = [x for x in b if x not in a]
        label = ".".join(path)
        for x in added:
            lines.append(f"+ {label}: {x}")
        for x in removed:
            lines.append(f"- {label}: {x}")
    for k in sorted(set(before) | set(after)):
        if k in SECRET_KEYS or any(k == p[0] for p in UNION_ARRAYS):
            continue
        if before.get(k) != after.get(k):
            lines.append(f"~ {k}")
    return lines
