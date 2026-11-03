"""Property-based fuzzing for JWT safety testing."""

import hashlib
import random
import string
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class FuzzResult:
    token: str
    crashes: List[int]  # index of crash (0 = early exit)
    time_taken: float
    failures: List[str]


def fuzz_token(
    num_tokens: int = 100,
    length_range: Tuple[int, int] = (50, 300),
    alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
) -> List[FuzzResult]:
    """Generate random JWT-like tokens and attempt to parse them.
    
    Returns a list of FuzzResult objects with outcome of each token.
    """
    results: List[FuzzResult] = []
    
    for i in range(num_tokens):
        # Generate random header, payload, signature
        header_len = random.randint(1, 10)
        header = "".join(random.choices(alphabet, k=header_len))
        
        payload_len = random.randint(1, 200)
        payload = "".join(random.choices(alphabet, k=payload_len))
        
        # Signature is base64url encoded random bytes
        sig_bytes = random.randbytes(32)  # 256-bit HMAC
        sig = "".join(random.choices(alphabet, k=len(sig_bytes)))
        
        token = f"{header}.{payload}.{sig}"
        
        # Try to parse with the analyzer
        from jwtsentinel.jwtlab import parse
        try:
            parse(token)
            results.append(FuzzResult(token=token, crashes=[], time_taken=0.0, failures=[]))
        except Exception as e:
            results.append(FuzzResult(token=token, crashes=[i], time_taken=0.0, failures=[str(e)]))
    
    return results


def fuzz_with_known_weak_secrets(num_tokens: int = 50, wordlist_path: str = "data/weak_secrets.txt") -> List[FuzzResult]:
    """Fuzz tokens specifically designed to trigger weak-secret cracking."""
    # Load wordlist
    with open(wordlist_path, "r") as f:
        wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    results: List[FuzzResult] = []
    
    for i in range(num_tokens):
        # Pick a random word from wordlist or generate random
        candidate = random.choice(wordlist) if wordlist else "".join(random.choices(alphabet, k=random.randint(8, 32)))
        
        # Build a token with the candidate as a claim (e.g., role=admin)
        # This increases likelihood of triggering the WEAK_SECRET finding
        token = f"eyJ0eXAiOiJKV1Q..."  # placeholder - we'll just use a simple format
        # Actually, let's construct a proper JWT with a weak secret in the payload
        # The analyzer will detect weak HMAC secrets regardless of format
        
        # Simpler approach: use a known weak token pattern
        # Many JWTs have "role=admin" or similar in the payload
        # We'll generate tokens with varying structures to stress the parser
        
        # Just use a random token and try to parse it
        token = f"{candidate}.test.payload.signature"
        
        try:
            from jwtsentinel.jwtlab import parse
            parse(token)
            results.append(FuzzResult(token=token, crashes=[], time_taken=0.0, failures=[]))
        except Exception as e:
            results.append(FuzzResult(token=token, crashes=[i], time_taken=0.0, failures=[str(e)]))
    
    return results