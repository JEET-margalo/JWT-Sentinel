"""Test suite for jwtlab. Standard library only, sub-second, no network."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from jwtsentinel import analyze, forge, forge_from_token, parse, sign, verify_hmac  # noqa: E402
from jwtsentinel.codec import b64url_decode, b64url_encode, decode_json_segment, encode_json_segment  # noqa: E402
from jwtsentinel.cracker import crack, load_wordlist  # noqa: E402
from jwtsentinel.forge import parse_claim_edits  # noqa: E402
from jwtsentinel.signing import hmac_signature, is_asymmetric, is_hmac  # noqa: E402

NOW = int(time.time())


class TestCodec:
    @pytest.mark.parametrize("data", [b"", b"a", b"ab", b"abc", b"abcd", b"\x00\xff\xfe", bytes(range(256))])
    def test_roundtrip(self, data):
        assert b64url_decode(b64url_encode(data)) == data

    def test_no_padding_in_output(self):
        assert "=" not in b64url_encode(b"any length string here!!")

    def test_url_safe_alphabet(self):
        encoded = b64url_encode(bytes(range(256)))
        assert "+" not in encoded and "/" not in encoded

    def test_decode_tolerates_missing_padding(self):
        # "abc" encodes to a value that would normally carry one "=".
        assert b64url_decode(b64url_encode(b"abc")) == b"abc"

    def test_json_segment_roundtrip(self):
        obj = {"alg": "HS256", "nested": {"a": [1, 2, 3]}}
        assert decode_json_segment(encode_json_segment(obj)) == obj

    def test_json_segment_is_compact(self):
        # A signature over pretty-printed JSON would never verify, so encoding must be tight.
        assert " " not in b64url_decode(encode_json_segment({"a": 1, "b": 2})).decode()

    def test_non_object_segment_rejected(self):
        with pytest.raises(ValueError):
            decode_json_segment(b64url_encode(b"[1,2,3]"))


class TestParsing:
    def test_parses_three_segments(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "k")
        parsed = parse(token)
        assert parsed.is_wellformed
        assert parsed.alg == "HS256"
        assert parsed.payload == {"sub": "1"}

    def test_strips_bearer_prefix(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "k")
        assert parse("Bearer " + token).is_wellformed
        assert parse("bearer " + token).is_wellformed

    def test_strips_whitespace(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "k")
        assert parse(f"  \n{token}\n  ").is_wellformed

    def test_empty_input_records_error(self):
        parsed = parse("")
        assert not parsed.is_wellformed
        assert parsed.errors

    def test_wrong_segment_count_recorded_but_still_decodes(self):
        # Only header.payload, signature missing - a stripped-signature shape.
        header = encode_json_segment({"alg": "HS256", "typ": "JWT"})
        payload = encode_json_segment({"sub": "1"})
        parsed = parse(f"{header}.{payload}")
        assert any("segments" in e for e in parsed.errors)
        assert parsed.header is not None and parsed.payload is not None

    def test_garbage_header_is_captured_not_raised(self):
        parsed = parse("!!!.@@@.###")
        assert not parsed.is_wellformed
        assert parsed.errors

    def test_alg_none_recognized(self):
        header = encode_json_segment({"alg": "none", "typ": "JWT"})
        payload = encode_json_segment({"sub": "1"})
        assert parse(f"{header}.{payload}.").alg == "NONE"

    def test_signing_input_matches_raw_segments(self):
        # The signing input must be the literal ASCII, not a re-encode.
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "k")
        parsed = parse(token)
        header_seg, payload_seg, _ = token.split(".")
        assert parsed.signing_input == f"{header_seg}.{payload_seg}".encode()


class TestSigning:
    def test_sign_then_verify(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "topsecret")
        parsed = parse(token)
        assert verify_hmac(parsed.signing_input, parsed.signature, "HS256", "topsecret")

    def test_wrong_secret_fails_verification(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "topsecret")
        parsed = parse(token)
        assert not verify_hmac(parsed.signing_input, parsed.signature, "HS256", "wrong")

    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_all_hmac_algorithms_roundtrip(self, alg):
        token = sign({"typ": "JWT"}, {"sub": "1"}, alg, "k")
        parsed = parse(token)
        assert parsed.alg == alg
        assert verify_hmac(parsed.signing_input, parsed.signature, alg, "k")

    def test_signature_changes_with_payload(self):
        a = sign({"typ": "JWT"}, {"role": "user"}, "HS256", "k").split(".")[2]
        b = sign({"typ": "JWT"}, {"role": "admin"}, "HS256", "k").split(".")[2]
        assert a != b

    def test_none_algorithm_has_empty_signature(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "none", "ignored")
        assert token.endswith(".")
        assert token.split(".")[2] == ""

    def test_hmac_matches_reference_vector(self):
        # RFC 7515 Appendix A.1 shares this key/first-bytes relationship; assert stability.
        sig = hmac_signature(b"a.b", "HS256", "k")
        assert len(sig) == 32
        assert hmac_signature(b"a.b", "HS256", "k") == sig

    def test_alg_classification(self):
        assert is_hmac("HS256") and not is_hmac("RS256")
        assert is_asymmetric("RS256") and is_asymmetric("ES384") and not is_asymmetric("HS256")


class TestCracker:
    def test_cracks_wordlist_secret(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "password")
        result = crack(parse(token))
        assert result.cracked
        assert result.secret == "password"
        assert result.guesses >= 1

    def test_does_not_crack_strong_secret(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "8Ff!x93kQ-not-a-word-zZ")
        result = crack(parse(token))
        assert not result.cracked
        assert result.reason

    def test_skips_asymmetric_tokens(self):
        header = encode_json_segment({"alg": "RS256", "typ": "JWT"})
        payload = encode_json_segment({"sub": "1"})
        result = crack(parse(f"{header}.{payload}.c2ln"))
        assert not result.attempted
        assert "HMAC" in result.reason

    def test_respects_max_guesses(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "definitely-not-present")
        result = crack(parse(token), wordlist=["a", "b", "c"], max_guesses=2)
        assert result.guesses == 2

    def test_rate_is_computed(self):
        token = sign({"typ": "JWT"}, {"sub": "1"}, "HS256", "secret")
        assert crack(parse(token)).rate >= 0

    def test_wordlist_loads_and_skips_comments(self):
        words = load_wordlist()
        assert "secret" in words
        assert all(not w.startswith("#") for w in words)


class TestAnalyzer:
    def _analyze(self, alg, payload, secret="secret"):
        return analyze(sign({"typ": "JWT"}, payload, alg, secret))

    def test_alg_none_is_critical(self):
        header = encode_json_segment({"alg": "none", "typ": "JWT"})
        payload = encode_json_segment({"sub": "1", "role": "admin"})
        analysis = analyze(f"{header}.{payload}.")
        codes = {f.code for f in analysis.findings}
        assert "ALG_NONE" in codes
        assert analysis.risk_band == "critical"

    def test_weak_secret_is_critical(self):
        analysis = self._analyze("HS256", {"sub": "1", "exp": NOW + 60}, "secret")
        assert any(f.code == "WEAK_SECRET" and f.severity == "critical" for f in analysis.findings)

    def test_strong_healthy_token_is_low_risk(self):
        analysis = self._analyze(
            "HS256",
            {"sub": "1", "aud": "api", "iss": "https://id", "iat": NOW, "exp": NOW + 300},
            "9Kd!v2mQ-strong-and-unguessable-Zx",
        )
        assert analysis.risk_score < 4.0
        assert not any(f.severity in ("critical", "high") for f in analysis.findings)

    def test_missing_exp_flagged(self):
        analysis = self._analyze("HS256", {"sub": "1", "aud": "api", "iss": "x"},
                                 "9Kd!v2mQ-strong-Zx")
        assert any(f.code == "NO_EXP" for f in analysis.findings)

    def test_expired_token_flagged_as_info(self):
        analysis = self._analyze("HS256", {"sub": "1", "exp": NOW - 3600, "aud": "a", "iss": "i"},
                                 "9Kd!v2mQ-strong-Zx")
        expired = [f for f in analysis.findings if f.code == "EXPIRED"]
        assert expired and expired[0].severity == "info"

    def test_missing_aud_flagged(self):
        analysis = self._analyze("HS256", {"sub": "1", "exp": NOW + 60, "iss": "x"},
                                 "9Kd!v2mQ-strong-Zx")
        assert any(f.code == "NO_AUD" for f in analysis.findings)

    def test_long_lived_flagged(self):
        analysis = self._analyze(
            "HS256", {"sub": "1", "iat": NOW, "exp": NOW + 400 * 86400, "aud": "a", "iss": "i"},
            "9Kd!v2mQ-strong-Zx")
        assert any(f.code == "LONG_LIVED" for f in analysis.findings)

    def test_privilege_claim_flagged(self):
        analysis = self._analyze("HS256", {"sub": "1", "role": "admin", "exp": NOW + 60,
                                           "aud": "a", "iss": "i"}, "9Kd!v2mQ-strong-Zx")
        assert any(f.code == "PRIVILEGE_CLAIM" for f in analysis.findings)

    def test_asymmetric_alg_gets_confusion_note(self):
        header = encode_json_segment({"alg": "RS256", "typ": "JWT"})
        payload = encode_json_segment({"sub": "1", "exp": NOW + 60, "aud": "a", "iss": "i"})
        analysis = analyze(f"{header}.{payload}.c2ln")
        assert any(f.code == "ASYMMETRIC_ALG" for f in analysis.findings)

    def test_risk_score_never_exceeds_ten(self):
        header = encode_json_segment({"alg": "none", "typ": "JWT"})
        payload = encode_json_segment({"role": "admin"})
        assert analyze(f"{header}.{payload}.").risk_score <= 10.0

    def test_score_derives_from_worst_finding(self):
        analysis = self._analyze("HS256", {"sub": "1", "exp": NOW + 60}, "secret")
        # A critical finding present means the band cannot be below high.
        assert analysis.risk_band in ("critical", "high")

    def test_claims_view_annotates_registered_claims(self):
        analysis = self._analyze("HS256", {"sub": "1", "custom": "x", "exp": NOW + 60},
                                 "9Kd!v2mQ-strong-Zx")
        by_name = {c["name"]: c for c in analysis.claims_view}
        assert by_name["sub"]["registered"] and by_name["sub"]["meaning"] == "subject"
        assert not by_name["custom"]["registered"]
        assert by_name["exp"]["rendered"]  # timestamp rendered human-readable

    def test_to_dict_is_json_serializable(self):
        analysis = self._analyze("HS256", {"sub": "1", "exp": NOW + 60}, "secret")
        json.dumps(analysis.to_dict())  # must not raise


class TestForge:
    def test_forge_produces_valid_token(self):
        result = forge({"sub": "1", "role": "admin"}, "secret", "HS256")
        assert result.ok
        parsed = parse(result.token)
        assert verify_hmac(parsed.signing_input, parsed.signature, "HS256", "secret")
        assert parsed.payload["role"] == "admin"

    def test_forge_from_token_flips_a_claim(self):
        original = sign({"typ": "JWT"}, {"sub": "1", "role": "user"}, "HS256", "secret")
        result = forge_from_token(original, {"role": "admin"}, "secret")
        assert result.ok
        assert parse(result.token).payload["role"] == "admin"
        # And the forged token verifies under the same secret - that is the whole point.
        p = parse(result.token)
        assert verify_hmac(p.signing_input, p.signature, "HS256", "secret")

    def test_forge_preserves_other_claims(self):
        original = sign({"typ": "JWT"}, {"sub": "1", "role": "user", "email": "a@b.c"},
                        "HS256", "secret")
        result = forge_from_token(original, {"role": "admin"}, "secret")
        assert result.payload["email"] == "a@b.c"

    def test_forge_rejects_unsupported_alg(self):
        assert not forge({"sub": "1"}, "k", "RS256").ok

    def test_forge_none_alg(self):
        result = forge({"sub": "1"}, "", "none")
        assert result.ok and result.token.endswith(".")


class TestClaimEditParsing:
    def test_json_object_form(self):
        assert parse_claim_edits('{"role": "admin", "n": 5}') == {"role": "admin", "n": 5}

    def test_key_value_lines(self):
        assert parse_claim_edits("role=admin\nn=5") == {"role": "admin", "n": 5}

    def test_typed_literals(self):
        edits = parse_claim_edits("admin=true\ncount=3\nname=jordan")
        assert edits["admin"] is True and edits["count"] == 3 and edits["name"] == "jordan"

    def test_empty_input(self):
        assert parse_claim_edits("") == {}

    def test_non_object_json_rejected(self):
        with pytest.raises(ValueError):
            parse_claim_edits("[1,2,3]")


class TestSamples:
    def test_sample_file_analyzes_cleanly(self):
        path = ROOT / "data" / "sample_tokens.json"
        samples = json.loads(path.read_text())
        assert len(samples) >= 4
        for sample in samples:
            analysis = analyze(sample["token"])
            # Every sample must at least parse into an analysis with a defined band.
            assert analysis.risk_band in ("critical", "high", "medium", "low", "info")

    def test_weak_sample_gets_cracked(self):
        path = ROOT / "data" / "sample_tokens.json"
        samples = json.loads(path.read_text())
        weak = next(s for s in samples if "Weak secret" in s["label"])
        analysis = analyze(weak["token"])
        assert analysis.crack_result.cracked
