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
#: A sealed profile travels as ONE opaque string under this key. Servers that
#: deep-merge (aitherium.com's preferences route keeps keys absent from a PUT)
#: would otherwise change the signed bytes and fail every pull.
SEALED_KEY = "_sealed"
#: The public key (hex) of the device that made the seal. Not covered by the
#: signature and not needed to be: it only says WHICH trusted key to check with.
#: Naming a different trusted key makes the signature fail; naming an untrusted
#: one is refused before any check runs.
SIGNER_KEY = "_signer"
#: Everything a seal adds beside the payload.
ENVELOPE_KEYS = (SEAL_KEY, SIGNER_KEY)


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


def trusted_keys_path():
    from . import config
    return config.home() / "trusted-keys.json"


def trusted_keys() -> list[str]:
    """Every public key this machine accepts a seal from.

    AWSETTINGS_PUBLIC_KEY (one key, or several separated by commas) plus the
    device list `awsettings trust refresh` fetched from the registry: the public
    halves of the keys of every device this user has enrolled and not revoked.
    """
    out: list[str] = []
    pinned = _public_key_hex()
    if pinned:
        out.extend(k.strip().lower() for k in pinned.split(",") if k.strip())
    try:
        data = json.loads(trusted_keys_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    for entry in (data.get("keys") or []) if isinstance(data, dict) else []:
        key = entry.get("seal_pubkey") if isinstance(entry, dict) else None
        if isinstance(key, str) and key.strip():
            out.append(key.strip().lower())
    return sorted(set(out))


def _public_key_hex() -> str | None:
    """The key this machine TRUSTS, from AWSETTINGS_PUBLIC_KEY.

    Deliberately its own variable rather than deriving the public half from the
    local private key: a machine that only VERIFIES should not need a signing key
    on it at all, and deriving from the local key would make every machine trust
    whatever key it happens to hold — which verifies your own forgeries perfectly.
    """
    from . import config
    v = config.get("AWSETTINGS_PUBLIC_KEY")
    return v or None


def verify(profile: dict[str, Any], *, require_seal: bool = False) -> dict[str, Any]:
    """Return the settings payload, or raise. The only way to read a profile.

    `require_seal` promotes "unsealed" from allowed to refused, so a machine that
    has been given a public key cannot be downgraded by an attacker simply
    deleting the seal.
    """
    if not isinstance(profile, dict):
        raise UntrustedProfileError("profile is not an object")

    payload = {k: v for k, v in profile.items() if k not in ENVELOPE_KEYS}

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

    trusted = trusted_keys()
    if not trusted:
        raise UntrustedProfileError(
            "this profile is SEALED but this machine trusts no key, so there is "
            "nothing to check it against. Refusing: verifying against 'whatever key "
            "this machine happens to hold' would happily accept a forgery signed with "
            "that same key. Enrol the device (`adk enroll`), run `awsettings trust "
            "refresh`, or set AWSETTINGS_PUBLIC_KEY.")
    signer = profile.get(SIGNER_KEY)
    if signer is not None:
        signer = str(signer).strip().lower()
        if signer not in trusted:
            raise UntrustedProfileError(
                f"this profile was sealed by {signer[:16]}..., which is not one of this "
                f"user's enrolled devices. The settings were NOT applied. If the device "
                f"is new, run `awsettings trust refresh`; if it was revoked, this is "
                f"the refusal working.")
        candidates = [signer]
    else:
        candidates = trusted       # a seal from before signers were named

    body, sig = payload_bytes(payload), _sig_bytes(seal)
    last: Exception | None = None
    for pub in candidates:
        try:
            mod.load_public_key(pub).verify(sig, body)
            return payload
        except Exception as exc:                               # noqa: BLE001
            last = exc
    try:
        raise last if last else UntrustedProfileError("no key verified the seal")
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
    out = {k: v for k, v in payload.items() if k not in ENVELOPE_KEYS}
    sig = priv.sign(payload_bytes(out)).hex()
    try:
        signer = mod.public_key_hex(priv)
    except Exception:                                          # noqa: BLE001
        signer = None
    out[SEAL_KEY] = sig
    if signer:
        out[SIGNER_KEY] = signer
    return out


def to_wire(profile: dict[str, Any]) -> dict[str, Any]:
    """A sealed profile as {_sealed: <canonical json>, _seal: hex}; unsealed unchanged."""
    if not is_sealed(profile):
        return profile
    payload = {k: v for k, v in profile.items() if k not in ENVELOPE_KEYS}
    wire = {SEALED_KEY: payload_bytes(payload).decode("utf-8"), SEAL_KEY: profile[SEAL_KEY]}
    if profile.get(SIGNER_KEY):
        wire[SIGNER_KEY] = profile[SIGNER_KEY]
    return wire


def from_wire(stored: dict[str, Any]) -> dict[str, Any]:
    """Inverse of to_wire. Any key the server merged in beside the envelope is
    DROPPED, never applied: only the signed bytes are trusted."""
    blob = stored.get(SEALED_KEY) if isinstance(stored, dict) else None
    if blob is None:
        return stored
    if not isinstance(blob, str):
        raise UntrustedProfileError(f"{SEALED_KEY} is not a string")
    try:
        payload = json.loads(blob)
    except ValueError as exc:
        raise UntrustedProfileError(f"{SEALED_KEY} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise UntrustedProfileError(f"{SEALED_KEY} is not an object")
    out = {k: v for k, v in payload.items() if k not in ENVELOPE_KEYS}
    for key in ENVELOPE_KEYS:
        if key in stored:
            out[key] = stored[key]
    return out
