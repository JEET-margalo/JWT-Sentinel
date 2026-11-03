#!/usr/bin/env python3
"""Generate the demo tokens the web UI offers as one-click examples.

Every token here is synthetic and self-signed with a deliberately weak or absent secret,
so nothing in this file is a real credential. Output is a JSON list the API serves.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jwtlab import sign  # noqa: E402
from jwtlab.codec import encode_json_segment  # noqa: E402

OUT = Path(__file__).resolve().parent / "sample_tokens.json"

# Timestamps are relative to generation time so the "live" samples never drift into
# looking expired - the flagship weak-secret demo should showcase the crack, not a
# stale exp. The expired sample is deliberately in the past.
IAT = int(time.time())
SOON = IAT + 900          # 15 minutes
LONG = IAT + 400 * 86400  # ~13 months, to trigger the long-lived finding
PAST = IAT - 30 * 86400


def alg_none_token() -> str:
    """A token with alg=none and an empty signature."""
    header = encode_json_segment({"typ": "JWT", "alg": "none"})
    payload = encode_json_segment({"sub": "1", "role": "user", "iat": IAT})
    return f"{header}.{payload}."


def samples() -> list[dict]:
    return [
        {
            "label": "Weak secret + admin claim",
            "hint": "HS256 signed with a wordlist secret, carrying role=admin. Watch it crack.",
            "token": sign({"typ": "JWT"},
                          {"sub": "1024", "name": "Jordan Lee", "role": "admin",
                           "iat": IAT, "exp": LONG}, "HS256", "secret"),
        },
        {
            "label": "alg: none",
            "hint": "No signature at all - the classic auth bypass.",
            "token": alg_none_token(),
        },
        {
            "label": "Expired token",
            "hint": "Well-signed but past its exp. A correct server rejects it.",
            "token": sign({"typ": "JWT"},
                          {"sub": "77", "email": "user@example.com", "aud": "billing-api",
                           "iss": "https://id.example.com", "iat": PAST, "exp": PAST + 3600},
                          "HS256", "a-genuinely-long-random-value-not-in-any-wordlist-42"),
        },
        {
            "label": "No expiry, no audience",
            "hint": "Strong secret, but the token never expires and can be replayed anywhere.",
            "token": sign({"typ": "JWT"},
                          {"sub": "9001", "scope": "read write", "iat": IAT},
                          "HS512", "Zx7!kP2$mQ9&vL4^rT8*wN6@cH1%bF3"),
        },
        {
            "label": "Healthy token",
            "hint": "Strong secret, short-lived, scoped audience and issuer. Little to flag.",
            "token": sign({"typ": "JWT"},
                          {"sub": "42", "aud": "orders-api", "iss": "https://id.example.com",
                           "iat": IAT, "nbf": IAT, "exp": SOON, "jti": "b1f9c2"},
                          "HS256", "n8Qv!2wReT6yUiOp0aSdFgHjKlZxCvBnM4"),
        },
    ]


def main() -> None:
    OUT.write_text(json.dumps(samples(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    for s in samples():
        print(f"  {s['label']:<28} {s['token'][:48]}…")


if __name__ == "__main__":
    main()
