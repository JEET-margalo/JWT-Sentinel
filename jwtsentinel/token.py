"""JWT parsing into an inspectable structure.

Parsing here is deliberately lenient: a security tool needs to inspect malformed and
malicious tokens, not reject them. The parser records what it could and could not
decode rather than raising on the first problem, so the analyzer can reason about
tokens that a strict library would refuse outright.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .codec import b64url_decode, decode_json_segment


@dataclass
class ParsedToken:
    raw: str
    parts: list[str] = field(default_factory=list)
    header: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    signature: bytes = b""
    signature_segment: str = ""
    # The exact bytes the signature is computed over: "<header>.<payload>".
    signing_input: bytes = b""
    errors: list[str] = field(default_factory=list)

    @property
    def alg(self) -> str:
        """The declared algorithm, upper-cased. `none` is a real, dangerous value."""
        if self.header and "alg" in self.header:
            return str(self.header["alg"]).upper()
        return "UNKNOWN"

    @property
    def typ(self) -> str | None:
        return self.header.get("typ") if self.header else None

    @property
    def is_wellformed(self) -> bool:
        return len(self.parts) == 3 and self.header is not None and self.payload is not None


def parse(token: str) -> ParsedToken:
    """Parse a compact-serialization JWT, tolerating malformed input."""
    token = token.strip()
    # People paste "Bearer <token>" straight out of an Authorization header.
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parsed = ParsedToken(raw=token)

    if not token:
        parsed.errors.append("empty input")
        return parsed

    parsed.parts = token.split(".")
    if len(parsed.parts) != 3:
        parsed.errors.append(
            f"expected 3 dot-separated segments, found {len(parsed.parts)} "
            "(a JWS compact token is header.payload.signature)"
        )
        # Still try to decode whatever segments are present.

    header_seg = parsed.parts[0] if len(parsed.parts) > 0 else ""
    payload_seg = parsed.parts[1] if len(parsed.parts) > 1 else ""
    parsed.signature_segment = parsed.parts[2] if len(parsed.parts) > 2 else ""

    try:
        parsed.header = decode_json_segment(header_seg)
    except Exception as exc:  # noqa: BLE001 - surface any decode failure to the report
        parsed.errors.append(f"header did not decode as base64url JSON: {exc}")

    try:
        parsed.payload = decode_json_segment(payload_seg)
    except Exception as exc:  # noqa: BLE001
        parsed.errors.append(f"payload did not decode as base64url JSON: {exc}")

    if parsed.signature_segment:
        try:
            parsed.signature = b64url_decode(parsed.signature_segment)
        except Exception as exc:  # noqa: BLE001
            parsed.errors.append(f"signature is not valid base64url: {exc}")

    # The signing input is the raw ASCII, not a re-encoding - re-serializing the header
    # could reorder keys and change the bytes the signature was actually computed over.
    parsed.signing_input = f"{header_seg}.{payload_seg}".encode("ascii", errors="replace")

    return parsed
