"""JWKS (JSON Web Key Set) fetching module for asymmetric JWT verification."""

import json
import time
from typing import Any, Dict, List, Optional

import requests


class JWKS:
    """Simple JWKS fetcher for JWT verification."""
    
    def __init__(self, jwks_url: str, cache_timeout: int = 300):
        self.jwks_url = jwks_url
        self.cache_timeout = cache_timeout
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp = 0
    
    def fetch(self) -> Dict[str, Any]:
        """Fetch JWKS from URL, using cache if recent."""
        now = time.time()
        if self._cache and (now - self._cache_timestamp) < self.cache_timeout:
            return self._cache
        
        try:
            response = requests.get(self.jwks_url, timeout=10)
            response.raise_for_status()
            self._cache = response.json()
            self._cache_timestamp = now
            return self._cache
        except Exception as e:
            raise RuntimeError(f"Failed to fetch JWKS: {e}")
    
    def get_key(self, kid: str) -> Optional[Dict[str, Any]]:
        """Get a specific key by kid (key id)."""
        jwks = self.fetch()
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None
    
    def get_all_keys(self) -> List[Dict[str, Any]]:
        """Get all keys."""
        return self.fetch().get("keys", [])


def decode_jwt_with_jwks(token: str, jwks_url: str) -> Dict[str, Any]:
    """Parse and verify a JWT using JWKS for asymmetric algorithms."""
    from jwtsentinel.jwtlab import parse
    from jwtsentinel.jwtlab.signing import verify_hmac, verify_rsa
    
    parsed = parse(token)
    
    if parsed.alg.startswith("RS") or parsed.alg.startswith("ES") or parsed.alg.startswith("PS"):
        # Asymmetric verification - need JWKS
        jwks = JWKS(jwks_url)
        key = jwks.get_key(parsed.header.get("kid"))
        if not key:
            raise ValueError(f"Key ID {parsed.header.get('kid')} not found in JWKS")
        
        # Simple verification stub - actual verification would be more complex
        # This is just to demonstrate the concept
        return {"wellformed": parsed.is_wellformed, "algorithm": parsed.alg, "key_id": parsed.header.get("kid")}
    
    else:
        # HMAC verification - use secret
        raise NotImplementedError("HMAC verification with external secret not implemented yet")