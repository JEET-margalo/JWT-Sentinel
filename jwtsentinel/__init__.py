"""jwtsentinel - JWT Sentinel: advanced JWT security toolkit."""
__version__ = "1.1.0"
from .analyzer import Analysis, Finding, analyze
from .cracker import CrackResult, crack, load_wordlist
from .forge import ForgeResult, forge, forge_from_token, parse_claim_edits
from .signing import is_asymmetric, is_hmac, sign, verify_hmac
from .token import ParsedToken, parse
# Advanced modules
from .fuzz import fuzz_token, fuzz_with_known_weak_secrets
from .policy import PolicyEngine, check_policy
from .jwks import JWKS, decode_jwt_with_jwks
from .export import to_sarif, to_junit
from .advanced_cracker import crack_advanced, AdvancedCrackResult
__all__ = [
    "__version__",
    "Analysis",
    "Finding",
    "analyze",
    "CrackResult",
    "crack",
    "load_wordlist",
    "ForgeResult",
    "forge",
    "forge_from_token",
    "parse_claim_edits",
    "is_asymmetric",
    "is_hmac",
    "sign",
    "verify_hmac",
    "ParsedToken",
    "parse",
    "fuzz_token",
    "fuzz_with_known_weak_secrets",
    "PolicyEngine",
    "check_policy",
    "JWKS",
    "decode_jwt_with_jwks",
    "to_sarif",
    "to_junit",
    "crack_advanced",
    "AdvancedCrackResult",
]