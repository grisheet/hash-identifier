"""
Command-line interface.

Reads hashes from positional arguments, a file (-f), or stdin, runs each
through the detection engine, and prints ranked results as either
human-readable text or JSON (--json) for machine consumption / piping.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable, Iterator, TextIO

from .cracking import suggestions
from .engine import HashIdentifier, Identification

# ANSI colours, auto-disabled when stdout is not a TTY.
_COLOR = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


# ---------------------------------------------------------------------------
# Input gathering.
# ---------------------------------------------------------------------------
def _iter_inputs(args: argparse.Namespace, stdin: TextIO) -> Iterator[str]:
    """Yield raw hash strings from args / file / stdin, in that precedence."""
    produced = False
    if args.hashes:
        produced = True
        yield from args.hashes
    if args.file:
        produced = True
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            yield from fh
    # Fall back to stdin only if nothing else was supplied and data is piped.
    if not produced and not stdin.isatty():
        yield from stdin


# ---------------------------------------------------------------------------
# Rendering.
# ---------------------------------------------------------------------------
def _render_text(
    ident: Identification, top: int, show_reasoning: bool, show_hashcat: bool
) -> str:
    lines: list[str] = []
    header = ident.value if len(ident.value) <= 74 else ident.value[:71] + "..."
    lines.append(_c(header, "1;36"))
    if not ident.candidates:
        lines.append(" " + _c("No match found.", "33"))
        if show_reasoning:
            for r in ident.reasoning:
                lines.append(" - " + r)
        return "\n".join(lines)

    for rank, cand in enumerate(ident.candidates[:top], start=1):
        bar_len = int(cand.confidence * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        conf = f"{cand.confidence * 100:5.1f}%"
        line = (
            f" {rank}. {cand.name:<12} {_c(bar, '32')} {conf}"
            f" [hashcat -m {cand.hashcat_mode}]"
        )
        lines.append(line)
        if show_hashcat:
            sug = suggestions(cand)
            if sug["hashcat"]:
                lines.append(" $ " + _c(sug["hashcat"], "90"))
            if sug["john"]:
                lines.append(" $ " + _c(sug["john"], "90"))

    if show_reasoning:
        lines.append(_c(" reasoning:", "1"))
        for r in ident.reasoning:
            lines.append(" - " + r)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hashid",
        description="Identify the most likely type(s) of a hash.",
        epilog="Examples:\n"
        " hashid 5f4dcc3b5aa765d61d8327deb882cf99\n"
        " hashid -f hashes.txt --json\n"
        " cat dump.txt | hashid --top 5 --hashcat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("hashes", nargs="*", help="one or more hashes to identify")
    p.add_argument("-f", "--file", help="read hashes from a file (one per line)")
    p.add_argument(
        "-t", "--top", type=int, default=3, help="max candidates to show (default: 3)"
    )
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument(
        "--hashcat",
        action="store_true",
        help="print ready-to-run hashcat/john command suggestions",
    )
    p.add_argument(
        "--no-reasoning",
        dest="reasoning",
        action="store_false",
        help="suppress the length/charset/entropy explanation",
    )
    p.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="hide candidates below this confidence (0..1)",
    )
    return p


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------
def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    engine = HashIdentifier()

    inputs = _iter_inputs(args, sys.stdin)
    results = engine.identify_many(inputs, top=max(args.top, 1))

    json_batch: list[dict] = []
    any_output = False

    for _, ident in results:
        any_output = True
        # Apply confidence floor.
        ident.candidates = [
            c for c in ident.candidates if c.confidence >= args.min_confidence
        ]
        if args.json:
            json_batch.append(ident.as_dict(top=args.top))
        else:
            print(
                _render_text(
                    ident,
                    top=args.top,
                    show_reasoning=args.reasoning,
                    show_hashcat=args.hashcat,
                )
            )
            print()

    if args.json:
        json.dump(json_batch, sys.stdout, indent=2)
        sys.stdout.write("\n")

    if not any_output:
        build_parser().print_help(sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
