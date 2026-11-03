"""base64url + JOSE segment codec.

JWTs are three base64url segments joined by dots. base64url is ordinary base64 with
`+/` swapped for `-_` and the `=` padding stripped - the padding is what trips people
up, because the decoder still needs it restored to a multiple of four.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    """Decode an unpadded base64url string, restoring the stripped padding."""
    # A base64 group is 4 chars; pad up to the next multiple of 4.
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_json_segment(segment: str) -> dict[str, Any]:
    """Decode one base64url JSON segment (the header or the payload)."""
    raw = b64url_decode(segment)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("segment is valid JSON but not an object")
    return value


def encode_json_segment(obj: dict[str, Any]) -> str:
    """Encode a dict as a compact base64url JSON segment.

    Separators are compacted (no spaces) so the output matches what real JWT libraries
    emit - a signature computed over pretty-printed JSON would never verify.
    """
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b64url_encode(raw)
