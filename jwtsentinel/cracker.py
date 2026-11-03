"""Dictionary attack against an HMAC-signed token.

This is exactly the attack an adversary runs after capturing a token: HS256 signatures
can be checked offline at millions of guesses per second, so any secret a wordlist
contains is already broken. The point of surfacing it here is to make that immediate and
visceral - if this tool finds the secret in a tenth of a second, so does everyone else.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .signing import is_hmac, verify_hmac
from .token import ParsedToken

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "weak_secrets.txt"


@dataclass
class CrackResult:
    attempted: bool
    cracked: bool
    secret: str | None = None
    guesses: int = 0
    elapsed_seconds: float = 0.0
    reason: str = ""

    @property
    def rate(self) -> int:
        """Guesses per second - a lower bound on how fast a real attacker goes."""
        if self.elapsed_seconds <= 0:
            return self.guesses
        return int(self.guesses / self.elapsed_seconds)


def load_wordlist(path: Path | None = None) -> list[str]:
    source = path or DEFAULT_WORDLIST
    words: list[str] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    return words


def crack(parsed: ParsedToken, wordlist: list[str] | None = None,
          max_guesses: int = 100_000) -> CrackResult:
    """Try each secret in the wordlist against the token's signature.

    `max_guesses` bounds the work so an oversized wordlist can never turn a web request
    into a denial of service.
    """
    if not is_hmac(parsed.alg):
        return CrackResult(
            attempted=False, cracked=False,
            reason=f"{parsed.alg} is not an HMAC algorithm; a dictionary attack does not apply",
        )
    if not parsed.signature or not parsed.signing_input:
        return CrackResult(attempted=False, cracked=False, reason="no signature to test against")

    words = wordlist if wordlist is not None else load_wordlist()
    start = time.perf_counter()
    guesses = 0

    for secret in words:
        if guesses >= max_guesses:
            break
        guesses += 1
        if verify_hmac(parsed.signing_input, parsed.signature, parsed.alg, secret):
            return CrackResult(
                attempted=True, cracked=True, secret=secret, guesses=guesses,
                elapsed_seconds=time.perf_counter() - start,
            )

    return CrackResult(
        attempted=True, cracked=False, guesses=guesses,
        elapsed_seconds=time.perf_counter() - start,
        reason="secret not found in the common-secret wordlist",
    )
