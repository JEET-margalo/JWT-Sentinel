"""Token forging - the payoff that makes the weak-secret finding concrete.

Once the secret is known, forging is trivial: change any claim and re-sign. This module
exists so the tool can show, not just assert, that a recovered secret means full control
over the token's contents. It signs only with a secret the caller supplies against a
token the caller supplied - it is a demonstration of consequence, not an attack on a
third party.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .signing import HMAC_ALGORITHMS, sign
from .token import parse


@dataclass
class ForgeResult:
    ok: bool
    token: str = ""
    header: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    error: str = ""


def forge(payload: dict[str, Any], secret: str, alg: str = "HS256",
          header: dict[str, Any] | None = None) -> ForgeResult:
    """Sign an arbitrary payload into a valid token."""
    alg = alg.upper()
    if alg != "NONE" and alg not in HMAC_ALGORITHMS:
        return ForgeResult(ok=False, error=f"unsupported algorithm for forging: {alg}")

    header = {"typ": "JWT", **(header or {}), "alg": alg}
    try:
        token = sign(header, payload, alg, secret)
    except Exception as exc:  # noqa: BLE001
        return ForgeResult(ok=False, error=str(exc))
    return ForgeResult(ok=True, token=token, header=header, payload=payload)


def forge_from_token(original: str, claim_edits: dict[str, Any], secret: str,
                     alg: str | None = None) -> ForgeResult:
    """Take an existing token, apply claim edits, and re-sign it.

    This is the exact operation an attacker performs after cracking the secret: keep the
    structure, flip `role` to `admin` or extend `exp`, and mint a token the server will
    accept as genuine.
    """
    parsed = parse(original)
    if parsed.payload is None:
        return ForgeResult(ok=False, error="original token payload could not be decoded")

    payload = {**parsed.payload, **claim_edits}
    header = dict(parsed.header or {})
    use_alg = (alg or parsed.alg or "HS256").upper()
    if use_alg == "UNKNOWN":
        use_alg = "HS256"
    return forge(payload, secret, use_alg, header)


def parse_claim_edits(raw: str) -> dict[str, Any]:
    """Parse the claim-edit input, which may be a full JSON object or key=value lines."""
    raw = raw.strip()
    if not raw:
        return {}
    # Anything that opens like JSON is parsed as JSON, so a stray array or literal is
    # rejected rather than silently misread as an empty set of key=value lines.
    if raw[0] in "{[\"" or raw[0].isdigit():
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("claim edits must be a JSON object")
        return value

    edits: dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Let obvious literals through as their real types.
        try:
            edits[key] = json.loads(value)
        except json.JSONDecodeError:
            edits[key] = value
    return edits
