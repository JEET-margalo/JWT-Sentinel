"""Advanced cracking modes for JWT Sentinel."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from jwtsentinel.cracker import CrackResult, crack
from jwtsentinel.signing import is_hmac
from jwtsentinel.token import ParsedToken


@dataclass
class AdvancedCrackResult:
    crack_result: CrackResult
    wordlist_used: str
    mode: str
    metadata: Optional[Dict[str, Any]] = None


def crack_advanced(
    parsed: ParsedToken,
    wordlist: Optional[List[str]] = None,
    mode: str = "dictionary",
    max_guesses: int = 100_000,
    custom_wordlist_path: Optional[str] = None,
) -> AdvancedCrackResult:
    if not is_hmac(parsed.alg):
        return AdvancedCrackResult(
            crack_result=CrackResult(
                attempted=False,
                cracked=False,
                reason=f"{parsed.alg} is not an HMAC algorithm",
            ),
            wordlist_used="",
            mode=mode,
            metadata={"guessed_key": None},
        )
    
    wordlist_used = "default"
    if custom_wordlist_path:
        wordlist_used = custom_wordlist_path
        with open(custom_wordlist_path, "r") as f:
            wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    if mode == "dictionary":
        crack_result = crack(parsed, wordlist=wordlist, max_guesses=max_guesses)
    elif mode == "mixed":
        all_words = []
        if wordlist:
            all_words.extend(wordlist)
        crack_result = crack(parsed, wordlist=all_words, max_guesses=max_guesses)
        wordlist_used = "combined"
    else:
        crack_result = crack(parsed, wordlist=wordlist, max_guesses=max_guesses)
    
    return AdvancedCrackResult(
        crack_result=crack_result,
        wordlist_used=wordlist_used,
        mode=mode,
        metadata={"guess_rate": crack_result.rate, "guessed_correct": crack_result.cracked},
    )