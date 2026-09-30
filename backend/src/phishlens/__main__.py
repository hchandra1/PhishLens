"""Command-line entry point: `python -m phishlens parse message.eml` (or `-` for stdin)."""

import argparse
import sys
from pathlib import Path

from phishlens.engine import analyze
from phishlens.models import Verdict
from phishlens.parser import EmailParseError, parse_email


def main() -> int:
    cli = argparse.ArgumentParser(prog="phishlens")
    commands = cli.add_subparsers(dest="command", required=True)
    parse_cmd = commands.add_parser("parse", help="Parse an email and print it as JSON.")
    parse_cmd.add_argument("path", help="Path to a .eml file, or - to read from stdin.")
    analyze_cmd = commands.add_parser("analyze", help="Analyze an email and print the verdict.")
    analyze_cmd.add_argument("path", help="Path to a .eml file, or - to read from stdin.")
    analyze_cmd.add_argument("--json", action="store_true", help="Print the Verdict as JSON.")
    args = cli.parse_args()

    raw = sys.stdin.buffer.read() if args.path == "-" else Path(args.path).read_bytes()
    try:
        parsed = parse_email(raw)
    except EmailParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.command == "parse":
        print(parsed.model_dump_json(indent=2, exclude={"html_body"}))
        return 0
    verdict = analyze(parsed)
    print(verdict.model_dump_json(indent=2) if args.json else _report(verdict))
    return 0


def _report(verdict: Verdict) -> str:
    lines = [
        f"{verdict.label.upper()}  (score {verdict.score:g}/100)",
        f"From: {verdict.email.from_display} <{verdict.email.from_address}>",
        f"Subject: {verdict.email.subject}",
        "",
        verdict.summary,
        "",
        "Why:",
    ]
    for signal in verdict.signals:
        lines.append(f"  [{signal.severity}] {signal.explanation}")
        lines += [f"      {e.label}: {e.value}" for e in signal.evidence]
    lines += ["", "What to do:", *(f"  - {a}" for a in verdict.recommended_actions)]
    skipped = [r for r in verdict.analyzers if r.status != "ok"]
    lines += [f"(Check '{r.analyzer}' did not run: {r.detail})" for r in skipped]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
