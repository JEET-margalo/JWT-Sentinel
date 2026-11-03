"""JWS signing and verification for the HMAC family.

Only HS256/384/512 are implemented, because those are the ones whose security collapses
to the strength of a shared secret - which is the whole point this tool demonstrates.
RS/ES/PS signing needs an asymmetric key the visitor does not have, so those tokens are
inspected and reasoned about but not verified here.
"""

from __future__ import annotations

import hashlib
import hmac

from .codec import b64url_encode, encode_json_segment

# JOSE `alg` value -> hashlib constructor.
HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

ASYMMETRIC_PREFIXES = ("RS", "ES", "PS", "ED")


def is_hmac(alg: str) -> bool:
    return alg.upper() in HMAC_ALGORITHMS


def is_asymmetric(alg: str) -> bool:
    return alg.upper().startswith(ASYMMETRIC_PREFIXES)


def hmac_signature(signing_input: bytes, alg: str, secret: str | bytes) -> bytes:
    """Compute the HMAC signature over the signing input."""
    digest = HMAC_ALGORITHMS.get(alg.upper())
    if digest is None:
        raise ValueError(f"unsupported HMAC algorithm: {alg}")
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    return hmac.new(key, signing_input, digest).digest()


def verify_hmac(signing_input: bytes, signature: bytes, alg: str, secret: str | bytes) -> bool:
    """Constant-time verification of an HMAC signature.

    `hmac.compare_digest` is used rather than `==` so the check itself does not leak the
    signature through timing - the same discipline the tool flags others for missing.
    """
    if not is_hmac(alg):
        return False
    try:
        expected = hmac_signature(signing_input, alg, secret)
    except ValueError:
        return False
    return hmac.compare_digest(expected, signature)


def sign(header: dict, payload: dict, alg: str, secret: str | bytes) -> str:
    """Produce a signed compact JWT.

    `alg` overrides whatever the header carries, so the caller can demonstrate an
    algorithm downgrade (e.g. re-signing an RS256 token as HS256) explicitly.
    """
    header = {**header, "alg": alg}
    signing_input = f"{encode_json_segment(header)}.{encode_json_segment(payload)}".encode("ascii")

    if alg.upper() == "NONE":
        # The "none" algorithm has an empty signature by definition.
        return signing_input.decode("ascii") + "."

    signature = hmac_signature(signing_input, alg, secret)
    return f"{signing_input.decode('ascii')}.{b64url_encode(signature)}"
