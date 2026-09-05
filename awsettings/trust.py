"""Is this profile really yours? — the optional signature port.

A settings profile is not data. It is an INSTRUCTION to a machine about what that
machine is allowed to do: anyone who can write your profile can add a
`permissions.allow` entry, and the next session on every device you own will
quietly adopt it. That is the one real attack on this design, and it is worth
closing properly rather than assuming the folder is safe.

`awseal` closes it — sign an artifact so a stranger can verify it, with an Ed25519
seal where the key that verifies is not the key that forges. This module is the
PORT, not a copy of it: awsettings never imports awseal at module scope and works
completely without it.

🚨 THE TRAP, and the whole reason this file exists.

The obvious way to make a dependency optional is:

    try:
        import awseal
    except ImportError:
        return True          # not installed, nothing to check

That is a **fail-open gate** (`security-review-patterns.md` #1), and here it is
worse than the general case: it hands an attacker a one-step bypass. Strip the
seal — or just make the verifier un-importable — and the client cheerfully applies
the profile it could not check. A verifier that returns True when it cannot verify
is not a weaker verifier; it is no verifier at all, with a comforting name.

So the decision is made by the PROFILE, not by what happens to be installed:

* profile carries **no seal**  -> nothing to verify. Trust is whatever the folder
  or endpoint already gives you, exactly as if this module did not exist. This is
  what keeps the brick adoptable alone — a stranger with two laptops and a
  synced folder needs no keys.
* profile carries **a seal**   -> verification is REQUIRED. A missing awseal, an
  unreadable key, or a bad signature are all the SAME answer: refuse. Never
  "skip", never "warn and continue".
* `AWSETTINGS_REQUIRE_SEAL=1`  -> an UNSEALED profile is refused too. Set this once
  you have signed, so that removing the seal cannot silently downgrade you.

The asymmetry is deliberate and is the point: adding a seal must be able to
tighten trust, and removing one must never be able to loosen it silently.
"""
from __future__ import annotations

import json
from typing import Any

#: Where the seal lives inside the profile object. A sibling of the settings
#: payload rather than inside it, so the signed bytes are exactly the payload.
SEAL_KEY = "_seal"


class UntrustedProfileError(Exception):
    """The profile could not be proven yours. Callers REFUSE — never apply."""


def is_sealed(profile: dict[str, Any]) -> bool:
    return isinstance(profile, dict) and bool(profile.get(SEAL_KEY))


def payload_bytes(payload: dict[str, Any]) -> bytes:
    """The exact bytes a seal covers.

    Canonical: sorted keys, no incidental whitespace. Two machines must derive
    byte-identical input from the same object or every signature fails for a
    reason that looks like tampering — the worst possible false positive, because
    it teaches people to turn verification off.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _load_awseal():
    """awseal's KEY module, or None. Import failure is NEVER a pass — see the
    docstring; every caller turns None into a refusal when a seal is present.

    🚩 It is `awseal.keys`, deliberately, and not `awseal.sign`/`awseal.verify`.
    Those are a FILE-TREE API — `sign(root: Path) -> Seal`, `verify(root: Path)
    -> dict` — built for sealing a directory of released artifacts. A settings
    profile is one JSON object, so materialising it into a temp tree just to seal
    it would be contorting this brick around the wrong half of that one.

    What awseal genuinely owns here is KEY MANAGEMENT: where the Ed25519 key
    lives, the `AWSEAL_KEY_PATH` env var, the default path, hex encoding of the
    public half. This port borrows exactly that and signs the canonical payload
    bytes directly — so one key, in awseal's own location, covers both planes.

    Written after assuming the byte-level shape and being wrong: the first
    version called `awseal.verify(payload, seal)` and got `verify() takes 1
    positional argument but 2 were given`. It failed CLOSED, which is why nothing
    was applied — but a guard that can only ever refuse is not a guard, it is an
    outage waiting for the first person who signs something.
    """
    try:
        from awseal import keys
        return keys
    except Exception:                                          # noqa: BLE001
        return None


def _sig_bytes(seal_value: Any) -> bytes:
    if not isinstance(seal_value, str):
        raise UntrustedProfileError("seal is not a hex string")
    try:
        return bytes.fromhex(seal_value)
    except ValueError as exc:
        raise UntrustedProfileError(f"seal is not valid hex: {exc}") from exc


def _public_key_hex() -> str | None:
    """The key this machine TRUSTS, from AWSETTINGS_PUBLIC_KEY.

    Deliberately its own variable rather than deriving the public half from the
    local private key: a machine that only VERIFIES should not need a signing key
    on it at all, and deriving from the local key would make every machine trust
    whatever key it happens to hold — which verifies your own forgeries perfectly.
    """
    import os
    v = (os.getenv("AWSETTINGS_PUBLIC_KEY") or "").strip()
    return v or None


def verify(profile: dict[str, Any], *, require_seal: bool = False) -> dict[str, Any]:
    """Return the settings payload, or raise. The only way to read a profile.

    `require_seal` promotes "unsealed" from allowed to refused, so a machine that
    has been given a public key cannot be downgraded by an attacker simply
    deleting the seal.
    """
    if not isinstance(profile, dict):
        raise UntrustedProfileError("profile is not an object")

    payload = {k: v for k, v in profile.items() if k != SEAL_KEY}

    if not is_sealed(profile):
        if require_seal:
            raise UntrustedProfileError(
                "AWSETTINGS_REQUIRE_SEAL is set and this profile carries no seal. "
                "Refusing: an unsigned profile is exactly what stripping a signature "
                "produces, so accepting one here would make the seal decorative.")
        return payload

    seal = profile[SEAL_KEY]
    mod = _load_awseal()
    if mod is None:
        raise UntrustedProfileError(
            "this profile is SEALED and awseal is not installed, so the seal cannot "
            "be checked. Refusing rather than applying it — `pip install awseal`. "
            "(Treating an absent verifier as a pass would let anyone bypass the "
            "signature by removing the verifier.)")

    pub = _public_key_hex()
    if pub is None:
        raise UntrustedProfileError(
            "this profile is SEALED but AWSETTINGS_PUBLIC_KEY is not set, so there is "
            "no key to check it against. Refusing: verifying against 'whatever key "
            "this machine happens to hold' would happily accept a forgery signed with "
            "that same key. Set it to the public half of the key you sign with "
            "(`python -c \"import awseal; print(awseal.public_key_hex())\"`).")

    try:
        mod.load_public_key(pub).verify(_sig_bytes(seal), payload_bytes(payload))
    except UntrustedProfileError:
        raise
    except Exception as exc:                                   # noqa: BLE001
        # cryptography raises InvalidSignature; anything else here (a malformed
        # key, a backend problem) is equally a "could not prove it" and gets the
        # same answer. There is no branch that continues.
        raise UntrustedProfileError(
            f"the seal on this profile did not verify ({type(exc).__name__}). The "
            f"settings were NOT applied. Either the profile was modified in transit, "
            f"or it was signed by a different key than the one this machine trusts."
        ) from exc
    return payload


def seal(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a payload with a seal. Raises when awseal is absent — a push that
    silently produced an UNSEALED profile would quietly downgrade every machine
    that pulls it."""
    mod = _load_awseal()
    if mod is None:
        raise UntrustedProfileError(
            "cannot sign: awseal is not installed (`pip install awseal`). Refusing "
            "to push an unsealed profile under a --sign flag: it would look signed "
            "to you and be unsigned to every machine that pulls it.")
    try:
        priv = mod.load_private_key()
    except Exception as exc:                                   # noqa: BLE001
        raise UntrustedProfileError(
            f"cannot sign: no usable signing key ({exc}). Generate one with "
            f"`python -c \"import awseal; awseal.keygen()\"`, or point "
            f"{mod.KEY_PATH_ENV} at an existing one.") from exc
    out = dict(payload)
    out[SEAL_KEY] = priv.sign(payload_bytes(payload)).hex()
    return out
