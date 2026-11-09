"""Command line entry point (read-only; the only write is --out)."""
from __future__ import annotations

import argparse
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cc-policy-lens",
                                description="Read-only security review of Claude Code settings.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="collect, merge and check settings")
    s.add_argument("--project", help="project directory to include (project/local layers, .mcp.json)")
    s.add_argument("--format", choices=("html", "json", "md"), default="json")
    s.add_argument("--out", help="report file to write (default: stdout)")
    s.add_argument("--lang", choices=("ko", "en"), default="ko", help="default report language")
    # Overrides for testing and unusual installs.
    s.add_argument("--home", help=argparse.SUPPRESS)
    s.add_argument("--managed-dir", help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        from .scan import run_scan
        return run_scan(args)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
