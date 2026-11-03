"""Policy-based JWT security rules for advanced testing."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class PolicyEngine:
    """A configurable policy engine that checks JWT claims against rules."""
    
    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules or []
        self.results: List[str] = []
    
    def add_rule(self, claim: str, required: bool = False, max_length: Optional[int] = None,
                 allowed_values: Optional[List[str]] = None, must_contain: Optional[str] = None):
        """Add a new policy rule for claim validation."""
        self.rules.append({
            "claim": claim,
            "required": required,
            "max_length": max_length,
            "allowed_values": allowed_values,
            "must_contain": must_contain,
        })
    
    def check_token(self, claims: Dict[str, Any]) -> List[str]:
        """Check token claims against all rules."""
        self.results = []
        for rule in self.rules:
            claim = rule.get("claim")
            required = rule.get("required", False)
            max_length = rule.get("max_length")
            allowed_values = rule.get("allowed_values")
            must_contain = rule.get("must_contain")
            
            if claim is None:
                continue
            
            # Check required
            if required and claim not in claims:
                self.results.append(f"POLICY_VIOLATION: Required claim '{claim}' is missing.")
                continue
            
            if claim not in claims:
                continue  # Not required and not present - skip
            
            value = claims[claim]
            
            # Check max_length (for strings)
            if max_length is not None:
                if isinstance(value, str) and len(value) > max_length:
                    self.results.append(f"POLICY_VIOLATION: Claim '{claim}' exceeds max length ({len(value)} > {max_length}).")
            
            # Check allowed_values
            if allowed_values is not None:
                if value not in allowed_values:
                    self.results.append(f"POLICY_VIOLATION: Claim '{claim}' has disallowed value '{value}'. Allowed: {allowed_values}.")
            
            # Check must_contain (for strings)
            if must_contain is not None:
                if isinstance(value, str) and must_contain not in value:
                    self.results.append(f"POLICY_VIOLATION: Claim '{claim}' must contain '{must_contain}'.")
        
        return self.results


def check_policy(token_claims: Dict[str, Any], rules_config_path: Optional[str] = None) -> List[str]:
    """Quick check policy function."""
    engine = PolicyEngine()
    # Default rules for JWT Sentinel
    engine.add_rule("exp", required=True, must_contain=None)
    engine.add_rule("aud", required=False, max_length=100, allowed_values=None)
    engine.add_rule("iss", required=False, allowed_values=None)
    return engine.check_token(token_claims)