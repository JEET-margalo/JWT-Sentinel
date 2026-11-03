"""JWT vulnerability analysis.

Produces an ordered list of findings from a parsed token plus, where applicable, the
result of a dictionary attack. Each finding names the weakness, explains why it matters
in one breath, and states the fix. The overall risk score is derived from the findings
rather than asserted, so it can never disagree with them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .cracker import CrackResult, crack
from .signing import is_asymmetric, is_hmac
from .token import ParsedToken, parse

SEVERITY_WEIGHT = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

# Registered claims (RFC 7519, section 4.1) and what each is for.
REGISTERED_CLAIMS = {
    "iss": "issuer",
    "sub": "subject",
    "aud": "audience",
    "exp": "expiration time",
    "nbf": "not before",
    "iat": "issued at",
    "jti": "JWT ID",
}

# Claim names that commonly carry authorization state - worth calling out because they
# are exactly what an attacker rewrites once the signature is forgeable.
PRIVILEGE_CLAIMS = ("role", "roles", "admin", "is_admin", "isAdmin", "scope", "scopes",
                    "permissions", "groups", "authorities", "acl", "privilege")

# A token good for longer than this is treated as excessive for an access token.
LONG_LIVED_SECONDS = 24 * 3600


@dataclass
class Finding:
    severity: str  # critical | high | medium | low | info
    code: str
    title: str
    detail: str
    fix: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
            "references": self.references,
        }


@dataclass
class Analysis:
    parsed: ParsedToken
    findings: list[Finding] = field(default_factory=list)
    crack_result: CrackResult | None = None
    claims_view: list[dict[str, Any]] = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        top = max(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        # Extra distinct problems nudge the score up without ever masking the worst one.
        distinct = len({f.code for f in self.findings if SEVERITY_WEIGHT[f.severity] >= 2.5})
        return round(min(10.0, top + 0.3 * max(0, distinct - 1)), 1)

    @property
    def risk_band(self) -> str:
        score = self.risk_score
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    def to_dict(self) -> dict[str, Any]:
        p = self.parsed
        return {
            "wellformed": p.is_wellformed,
            "parse_errors": p.errors,
            "algorithm": p.alg,
            "header": p.header,
            "payload": p.payload,
            "signature_b64": p.signature_segment,
            "claims": self.claims_view,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "findings": [f.to_dict() for f in self.findings],
            "crack": _crack_to_dict(self.crack_result) if self.crack_result else None,
        }


def _crack_to_dict(result: CrackResult) -> dict[str, Any]:
    return {
        "attempted": result.attempted,
        "cracked": result.cracked,
        "secret": result.secret,
        "guesses": result.guesses,
        "elapsed_seconds": round(result.elapsed_seconds, 4),
        "rate": result.rate,
        "reason": result.reason,
    }


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _fmt_ts(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError, OSError):
        return str(value)


def _humanize_delta(seconds: int) -> str:
    seconds = abs(int(seconds))
    if seconds < 90:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{hours // 24} day{'s' if hours // 24 != 1 else ''}"


# --------------------------------------------------------------------------
# Individual checks. Each takes the parsed token and appends any findings.
# --------------------------------------------------------------------------

def _check_alg_none(p: ParsedToken, out: list[Finding]) -> None:
    if p.alg != "NONE":
        return
    out.append(Finding(
        severity="critical",
        code="ALG_NONE",
        title='Algorithm is "none" - the signature is not checked',
        detail=(
            "The header declares alg=none, which tells a verifier to accept the token "
            "with no signature at all. Any server that honours this will trust a token "
            "an attacker assembled by hand, including any claims it contains."
        ),
        fix=(
            "Never accept alg=none. Pin the expected algorithm on the server "
            "(e.g. verify(token, key, algorithms=['HS256'])) and reject anything else."
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/",
                    "CVE-2015-9235"],
    ))


def _check_signature_presence(p: ParsedToken, out: list[Finding]) -> None:
    if p.alg in ("NONE", "UNKNOWN"):
        return
    if not p.signature:
        out.append(Finding(
            severity="high",
            code="NO_SIGNATURE",
            title="Algorithm claims to be signed but no signature is present",
            detail=(
                f"The header declares {p.alg}, yet the signature segment is empty. This is "
                "the shape of a stripped-signature attack - the token was signed once and "
                "the signature later removed to see whether the server still accepts it."
            ),
            fix="Reject tokens whose signature segment is empty for any signed algorithm.",
        ))


def _check_weak_secret(p: ParsedToken, crack_result: CrackResult | None, out: list[Finding]) -> None:
    if not crack_result or not crack_result.cracked:
        return
    out.append(Finding(
        severity="critical",
        code="WEAK_SECRET",
        title=f'HMAC secret recovered by dictionary attack: "{crack_result.secret}"',
        detail=(
            f"The signing secret was found in {crack_result.guesses} guesses in "
            f"{crack_result.elapsed_seconds:.3f}s (~{crack_result.rate:,} guesses/sec). "
            "With the secret known, anyone can forge a valid token carrying any claims "
            "they like - the signature stops being a security control."
        ),
        fix=(
            "Use a high-entropy secret of at least 256 bits from a CSPRNG "
            "(e.g. `openssl rand -base64 32`), store it in a secrets manager, and rotate "
            "it. Consider moving to asymmetric signing (RS256/ES256) so verifiers never "
            "hold the signing key at all."
        ),
        references=["https://owasp.org/www-community/vulnerabilities/Weak_JWT_Signing_Key"],
    ))


def _check_algorithm_confusion(p: ParsedToken, out: list[Finding]) -> None:
    if not is_asymmetric(p.alg):
        return
    out.append(Finding(
        severity="info",
        code="ASYMMETRIC_ALG",
        title=f"{p.alg} is asymmetric - verify the key type is enforced",
        detail=(
            "This token uses asymmetric signing, which cannot be verified here without the "
            "public key. Asymmetric tokens are the target of the algorithm-confusion attack: "
            "if a server verifies with a key object rather than a pinned algorithm, an "
            "attacker can re-sign the token as HS256 using the public key as the HMAC secret."
        ),
        fix=(
            "Pin the algorithm on verification to exactly the asymmetric scheme you issued "
            "with. Never let the token's own header choose between HMAC and RSA/EC."
        ),
        references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
    ))


def _check_expiry(p: ParsedToken, out: list[Finding]) -> None:
    if not p.payload:
        return
    now = _now()

    if "exp" not in p.payload:
        out.append(Finding(
            severity="medium",
            code="NO_EXP",
            title="No expiration (exp) claim",
            detail=(
                "The token never expires. A token captured from a log, a browser, or a "
                "proxy stays valid indefinitely, so a single leak is permanent."
            ),
            fix="Always set a short exp (minutes for access tokens) and refresh out-of-band.",
        ))
    else:
        exp = p.payload["exp"]
        try:
            exp_int = int(exp)
        except (TypeError, ValueError):
            out.append(Finding(
                severity="low", code="BAD_EXP",
                title="exp claim is not a numeric timestamp",
                detail=f"exp={exp!r} is not a NumericDate; verifiers may mis-handle it.",
                fix="Set exp to an integer count of seconds since the Unix epoch.",
            ))
            return
        if exp_int < now:
            out.append(Finding(
                severity="info",
                code="EXPIRED",
                title=f"Token expired {_humanize_delta(now - exp_int)} ago",
                detail=(
                    f"exp is {_fmt_ts(exp_int)}. A correct verifier rejects this token now - "
                    "which is the behaviour you want. It is flagged only so you notice."
                ),
                fix="No action if rejection is intended; re-issue if the token should be live.",
            ))
        else:
            lifetime = exp_int - int(p.payload.get("iat", now))
            if lifetime > LONG_LIVED_SECONDS:
                out.append(Finding(
                    severity="low",
                    code="LONG_LIVED",
                    title=f"Long-lived token (~{_humanize_delta(lifetime)})",
                    detail=(
                        "The window between issuance and expiry is wide, so a leaked token "
                        "stays useful to an attacker for a long time."
                    ),
                    fix="Shorten access-token lifetime; use refresh tokens for longevity.",
                ))


def _check_temporal_claims(p: ParsedToken, out: list[Finding]) -> None:
    if not p.payload:
        return
    now = _now()
    nbf = p.payload.get("nbf")
    if nbf is not None:
        try:
            if int(nbf) > now:
                out.append(Finding(
                    severity="info", code="NOT_YET_VALID",
                    title=f"Token is not valid until {_fmt_ts(nbf)}",
                    detail="The nbf (not-before) claim is in the future; a correct verifier "
                           "rejects the token until then.",
                    fix="No action if intentional.",
                ))
        except (TypeError, ValueError):
            pass


def _check_missing_identity_claims(p: ParsedToken, out: list[Finding]) -> None:
    if not p.payload:
        return
    if "aud" not in p.payload:
        out.append(Finding(
            severity="medium",
            code="NO_AUD",
            title="No audience (aud) claim",
            detail=(
                "Without aud, a token minted for one service is replayable against any other "
                "service that trusts the same key. This is how a token for a low-value API "
                "gets replayed against a privileged one."
            ),
            fix="Set aud to the intended recipient and verify it on every service.",
        ))
    if "iss" not in p.payload:
        out.append(Finding(
            severity="low",
            code="NO_ISS",
            title="No issuer (iss) claim",
            detail="Without iss, a verifier cannot confirm the token came from the expected "
                   "identity provider.",
            fix="Set iss to your token issuer and verify it.",
        ))


def _check_privilege_claims(p: ParsedToken, out: list[Finding]) -> None:
    if not p.payload:
        return
    present = [c for c in PRIVILEGE_CLAIMS if c in p.payload]
    if not present:
        return
    values = ", ".join(f"{c}={p.payload[c]!r}" for c in present)
    out.append(Finding(
        severity="info",
        code="PRIVILEGE_CLAIM",
        title=f"Authorization is carried in the token ({', '.join(present)})",
        detail=(
            f"The token encodes authorization state ({values}). This is fine only while the "
            "signature is unforgeable - the moment the algorithm or secret is weak, these "
            "are the exact fields an attacker rewrites to escalate."
        ),
        fix=(
            "Treat these claims as trusted only after strict signature verification, and "
            "prefer looking authorization up server-side from the subject rather than "
            "trusting a self-asserted role in the token."
        ),
    ))


def _build_claims_view(p: ParsedToken) -> list[dict[str, Any]]:
    """A row per payload claim, annotating registered claims and rendering timestamps."""
    if not p.payload:
        return []
    rows = []
    for key, value in p.payload.items():
        row: dict[str, Any] = {
            "name": key,
            "value": value,
            "registered": key in REGISTERED_CLAIMS,
            "meaning": REGISTERED_CLAIMS.get(key, ""),
            "rendered": None,
            "privileged": key in PRIVILEGE_CLAIMS,
        }
        if key in ("exp", "nbf", "iat") and isinstance(value, (int, float)):
            row["rendered"] = _fmt_ts(value)
        rows.append(row)
    return rows


def analyze(token: str, run_crack: bool = True, wordlist: list[str] | None = None) -> Analysis:
    """Parse and fully analyze a token."""
    parsed = parse(token)

    crack_result: CrackResult | None = None
    if run_crack and is_hmac(parsed.alg) and parsed.signature:
        crack_result = crack(parsed, wordlist=wordlist)

    findings: list[Finding] = []
    _check_alg_none(parsed, findings)
    _check_signature_presence(parsed, findings)
    _check_weak_secret(parsed, crack_result, findings)
    _check_algorithm_confusion(parsed, findings)
    _check_expiry(parsed, findings)
    _check_temporal_claims(parsed, findings)
    _check_missing_identity_claims(parsed, findings)
    _check_privilege_claims(parsed, findings)

    # Order by severity, worst first; preserve discovery order within a band.
    findings.sort(key=lambda f: -SEVERITY_WEIGHT[f.severity])

    return Analysis(
        parsed=parsed,
        findings=findings,
        crack_result=crack_result,
        claims_view=_build_claims_view(parsed),
    )
