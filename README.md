# JWT Sentinel

A next-generation JWT inspection, vulnerability-scanning and security-testing toolkit.

> **Authorized use only:** Use this toolkit only with JWTs and systems you own or have explicit permission to test. Do not use it to access, modify, or forge tokens belonging to other users or services.

Advanced testing mode — property-based fuzzing (`fuzz_token`), configurable policy
rules (`PolicyEngine`), JWKS fetching (`JWKS`), SARIF/JUnit export (`to_sarif`,
`to_junit`), and multi-mode dictionary cracking (`advanced_cracker`).

**Live demo:** [nikhilsec.com/projects/jwt-sentinel](https://github.com/JEET-margalo/JWT-Sentinel)

Paste a JSON Web Token, see exactly what it contains and where it is weak - then watch a
weak signing secret get recovered by dictionary attack in a fraction of a second, and
forge a token of your own to prove what that means.

**Live demo:** [nikhilsec.com/projects/jwt-inspector](https://github.com/JEET-margalo/JWT-Sentinel)

## What it is

A small, self-contained JWT security tool with a point: **a JWT is only as trustworthy as its
signature.** The moment the algorithm is `none` or the secret is guessable, every claim
in the token - including `role: admin` - is attacker-controlled. This makes that concrete
instead of abstract.

The whole thing is **pure Python standard library**. The JOSE base64url codec, HMAC
signing and verification, the cracker and the analyzer are all implemented from scratch -
no `PyJWT`, no `cryptography`. For a security tool that is a feature: you can read every
line that touches a signature.

## What it demonstrates

- **Decode & analyze** — parses header/payload/signature (including malformed/malicious
  tokens) and runs a battery of checks against them, deriving a risk score from the findings.
- **Crack** — recovers weak HMAC secrets via a bounded, rate-limited dictionary attack.
- **Forge** — takes a recovered secret, edits a claim, and re-signs a token that a naive
  verifier will accept as genuine, to prove the consequence of a weak secret concretely.
- **Sign** — builds a fresh, correctly-signed token from a set of claims, for testing.

## Requirements / tools

- Python 3 (standard library only — no runtime dependencies)
- `make` (optional, for the test target)

## Setup / usage

```bash
git clone https://github.com/JEET-margalo/JWT-Sentinel.git
cd jwt-inspector

# Inspect a token (decodes, analyzes, and attempts a dictionary crack)
python3 -m jwtsentinel.cli inspect eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Crack a weak HS256 secret
python3 -m jwtsentinel.cli crack <token>

# Forge: flip a claim and re-sign with a known secret
python3 -m jwtsentinel.cli forge <token> --set role=admin --secret secret

# Sign a fresh token from scratch
python3 -m jwtsentinel.cli sign --claim sub=42 --claim role=admin --secret secret
```

Or use it as a library:

```python
from jwtsentinel import analyze

result = analyze(token)
print(result.risk_score, result.risk_band)
for finding in result.findings:
    print(finding.severity, finding.title)
```

## What it checks

| Check | Severity | Why it matters |
|---|---|---|
| `alg: none` | critical | The signature is not verified at all - a hand-assembled token is trusted. |
| Weak HMAC secret | critical | Recovered by dictionary attack ⇒ anyone can forge valid tokens. |
| Stripped signature | high | Signed algorithm declared, but the signature segment is empty. |
| Algorithm confusion | info | Asymmetric token; flags the RS256→HS256 key-confusion risk. |
| No `exp` | medium | Token never expires; a single leak is permanent. |
| No `aud` | medium | Replayable against any service trusting the same key. |
| Expired / not-yet-valid | info | Temporal claims that a correct verifier already enforces. |
| Long-lived token | low | Wide leak-to-expiry window. |
| No `iss` | low | Issuer cannot be confirmed. |
| Privilege claims | info | `role`/`scope`/`admin` present - the fields an attacker rewrites first. |

The **risk score is derived from the findings**, not asserted alongside them, so the
number can never disagree with the list beneath it. The worst finding sets the floor;
additional distinct problems nudge it up without ever masking the top one.

## The cracker

`HS256` signatures are HMAC - verifiable offline at millions of guesses per second. That
is the entire threat model: if a token's secret is in a wordlist, it is already broken.

The bundled wordlist is the usual suspects - framework defaults, tutorial copy-paste, and
the top of every JWT cracking list. On the demo token the secret `"secret"` falls on the
first guess. The point of showing the elapsed time is that it is *small*: if this tool
finds it in a tenth of a second, so does everyone else.

Work is bounded (`max_guesses`) so an oversized wordlist can never turn a request into a
denial of service, and verification uses `hmac.compare_digest` - the same constant-time
comparison the tool flags others for missing.

## The forge

Once the secret is known, forging is trivial, and that triviality is the lesson. Give the
forger a token, an edit (`role=admin`), and the recovered secret, and it mints a token the
server will accept as genuine:

```bash
$ jwtsentinel forge <user-token> --set role=admin --secret secret
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.rC...
```

It signs only a token you supplied with a secret you supplied - a demonstration of
consequence, the same operation `jwt.io` performs, not an attack on anyone else.

## Project structure

```
jwtsentinel/
├── codec.py      base64url + JOSE segment encode/decode
├── token.py      lenient parser (inspects malformed/malicious tokens)
├── signing.py    HMAC sign/verify, constant-time, HS256/384/512
├── cracker.py    bounded dictionary attack
├── analyzer.py   the checks, the claim view, the derived risk score
├── forge.py      re-sign with edited claims
└── cli.py        inspect | crack | forge | sign
data/
├── weak_secrets.txt      the wordlist
├── generate_samples.py   builds the demo tokens (seeded, reproducible)
└── sample_tokens.json    five tokens spanning the failure modes
tests/            61 tests, standard library only, sub-second
```

## Testing

```bash
make test    # 61 tests
```

Structured around the properties that matter: **codec round-trips** across every byte
value and padding case, **sign→verify** for all three HMAC algorithms, the cracker both
*finding* weak secrets and *not* false-positiving on strong ones, and every analyzer check
paired against a healthy token that must stay quiet. A healthy, strong, short-lived token
scores under 4.0 - a scanner that cannot stay calm on good input is noise.

One bug the tests caught: the claim-edit parser accepted a JSON array (`[1,2,3]`) and
silently returned an empty edit set instead of rejecting it, because the array fell
through to the `key=value` line parser. Fixed to reject anything that opens like JSON but
is not an object.

## Skills demonstrated

- JOSE/JWT internals implemented from scratch against the standard library — base64url
  codec, HMAC sign/verify, lenient parsing of malformed tokens
- Applied cryptanalysis: bounded dictionary attacks against HMAC, with constant-time
  comparison used correctly where it matters
- Vulnerability-scanner design: deriving a single risk score from a findings list so the
  two can never disagree, instead of asserting a score independently
- Test design around security properties (round-trip correctness, true/false-positive rate,
  a "stays quiet on good input" baseline) rather than just line coverage

## Defensive / security takeaways

- **`alg: none` and weak HMAC secrets are still the two most common JWT implementation bugs**
  in the wild, and both are fully preventable by verifying the algorithm server-side and
  never trusting the token's declared `alg`.
- **A JWT's claims are only as trustworthy as the signature protecting them** — any service
  that trusts `role`/`scope` claims without verifying signature and algorithm is one weak
  secret away from full privilege escalation.
- **RS256/HS256 algorithm confusion** is a real attack class: if a verifier accepts either
  algorithm and uses the same key material for both, an attacker who obtains the RSA public
  key can use it as an HMAC secret to forge tokens.
- Always set `exp` and `aud` — an unexpirable, non-audience-scoped token turns a single leak
  into a permanent, cross-service compromise.

## Scope

- **HMAC only for signing/verifying.** RS/ES/PS tokens are decoded and reasoned about but
  not verified - that needs an asymmetric key the tool does not hold. The algorithm-
  confusion finding covers the risk they carry.
- **The wordlist is intentionally small.** It demonstrates the attack; it is not meant to
  be exhaustive. Point a real cracking rig at a captured token and assume anything
  human-memorable is already gone.

## Project page

[nikhilsec.com/projects/jwt-inspector](https://github.com/JEET-margalo/JWT-Sentinel)

## License

MIT — see [LICENSE](LICENSE).

---

<sub>Part of my security/engineering portfolio — more at <a href="https://github.com/JEET-margalo">JEET-margalo</a></sub>
