"""Command line interface.

    jwtsentinel inspect <token>
    jwtsentinel crack <token>
    jwtsentinel forge <token> --set role=admin --secret secret
    jwtsentinel sign --claim sub=123 --claim role=admin --secret secret
    echo "<token>" | jwtsentinel inspect -
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze
from .forge import forge, forge_from_token, parse_claim_edits

BAND_COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
              "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"
BOLD = "\033[1m"


def _color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


def _read_token(value: str) -> str:
    return sys.stdin.read().strip() if value == "-" else value


def cmd_inspect(args: argparse.Namespace) -> int:
    analysis = analyze(_read_token(args.token), run_crack=not args.no_crack)
    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2, default=str))
        return 0

    p = analysis.parsed
    print()
    print(f"  {_color('JWT INSPECTION', BOLD)}")
    print(f"  algorithm: {p.alg}   risk: "
          f"{_color(f'{analysis.risk_score}/10 {analysis.risk_band.upper()}', BAND_COLOR[analysis.risk_band])}")
    if p.errors:
        for err in p.errors:
            print(f"  {_color('parse:', BAND_COLOR['medium'])} {err}")

    print(f"\n  {_color('HEADER', BOLD)}   {json.dumps(p.header)}")
    print(f"  {_color('PAYLOAD', BOLD)}  {json.dumps(p.payload)}")

    if analysis.crack_result and analysis.crack_result.cracked:
        cr = analysis.crack_result
        print(f"\n  {_color('SECRET CRACKED', BAND_COLOR['critical'])}: "
              f'"{cr.secret}"  ({cr.guesses} guesses, {cr.elapsed_seconds:.3f}s)')

    print(f"\n  {_color('FINDINGS', BOLD)}")
    for f in analysis.findings:
        tag = _color(f"[{f.severity.upper()}]", BAND_COLOR[f.severity])
        print(f"  {tag} {f.title}")
        print(f"       {f.detail}")
        print(f"       {_color('fix:', BOLD)} {f.fix}\n")
    if not analysis.findings:
        print("  no issues detected\n")
    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    from .cracker import crack as run_crack
    from .token import parse

    result = run_crack(parse(_read_token(args.token)))
    if result.cracked:
        print(f'cracked: "{result.secret}"  ({result.guesses} guesses, '
              f'{result.elapsed_seconds:.3f}s, ~{result.rate:,}/sec)')
        return 0
    print(f"not cracked: {result.reason}")
    return 1


def cmd_forge(args: argparse.Namespace) -> int:
    edits = parse_claim_edits("\n".join(args.set or []))
    result = forge_from_token(_read_token(args.token), edits, args.secret, args.alg)
    if not result.ok:
        print(f"error: {result.error}", file=sys.stderr)
        return 2
    print(result.token)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    payload = parse_claim_edits("\n".join(args.claim or []))
    result = forge(payload, args.secret, args.alg)
    if not result.ok:
        print(f"error: {result.error}", file=sys.stderr)
        return 2
    print(result.token)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jwtsentinel", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"jwtsentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect", help="decode and analyze a token")
    inspect.add_argument("token", help="the JWT, or - to read from stdin")
    inspect.add_argument("--json", action="store_true", help="emit JSON")
    inspect.add_argument("--no-crack", action="store_true", help="skip the dictionary attack")
    inspect.set_defaults(func=cmd_inspect)

    crack = sub.add_parser("crack", help="dictionary-attack an HS* token")
    crack.add_argument("token")
    crack.set_defaults(func=cmd_crack)

    forge = sub.add_parser("forge", help="edit claims and re-sign an existing token")
    forge.add_argument("token")
    forge.add_argument("--set", action="append", help="claim edit, key=value (repeatable)")
    forge.add_argument("--secret", required=True)
    forge.add_argument("--alg", default=None)
    forge.set_defaults(func=cmd_forge)

    sign = sub.add_parser("sign", help="sign a fresh token from claims")
    sign.add_argument("--claim", action="append", help="key=value (repeatable)")
    sign.add_argument("--secret", required=True)
    sign.add_argument("--alg", default="HS256")
    sign.set_defaults(func=cmd_sign)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
