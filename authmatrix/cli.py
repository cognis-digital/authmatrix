"""Command-line interface for AUTHMATRIX."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze, load_matrix, summarize, Severity


def _read_json(path: str) -> dict:
    if path == "-":
        return json.loads(sys.stdin.read())
    with open(path, "r", encoding="utf-8") as fh:
        return json.loads(fh.read())


def _render_table(findings, counts) -> str:
    lines: List[str] = []
    lines.append("AUTHMATRIX %s - authorization coverage report" % TOOL_VERSION)
    lines.append("=" * 64)
    if not findings:
        lines.append("No authorization gaps found. All policy cells matched.")
        return "\n".join(lines)

    header = "%-9s %-12s %-14s %-9s %-9s %s" % (
        "SEVERITY", "ROLE", "ENDPOINT", "EXPECTED", "ACTUAL", "KIND",
    )
    lines.append(header)
    lines.append("-" * len(header))
    for f in findings:
        lines.append(
            "%-9s %-12s %-14s %-9s %-9s %s"
            % (
                f.severity.upper(),
                f.role[:12],
                f.endpoint[:14],
                f.expected,
                f.effective,
                f.kind,
            )
        )
    lines.append("-" * len(header))
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
             Severity.LOW, Severity.INFO]
    summary = "  ".join(
        "%s=%d" % (s, counts[s]) for s in order if counts.get(s)
    )
    lines.append("Summary: %d finding(s)  [%s]" % (len(findings), summary))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Test a role x endpoint access-control matrix for authorization "
            "gaps (IDOR / over-permission). Defensive / authorized use only."
        ),
    )
    parser.add_argument(
        "--version", action="version",
        version="%s %s" % (TOOL_NAME, TOOL_VERSION),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser(
        "scan",
        help="Analyze a matrix JSON artifact and report authorization gaps.",
    )
    p_scan.add_argument(
        "matrix",
        help="Path to matrix JSON file ('-' for stdin).",
    )
    p_scan.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).",
    )
    p_scan.add_argument(
        "--fail-on", choices=("critical", "high", "medium", "low", "info"),
        default="info",
        help=(
            "Minimum severity that triggers a non-zero exit "
            "(default: info = any finding)."
        ),
    )
    return parser


def _run_scan(args) -> int:
    try:
        data = _read_json(args.matrix)
        matrix = load_matrix(data)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    findings = analyze(matrix)
    counts = summarize(findings)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": {
                "total": len(findings),
                "by_severity": counts,
            },
            "findings": [f.to_dict() for f in findings],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(_render_table(findings, counts) + "\n")

    threshold = Severity.rank(args.fail_on)
    triggering = [f for f in findings if Severity.rank(f.severity) >= threshold]
    return 1 if triggering else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
