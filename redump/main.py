from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich_argparse import RichHelpFormatter

from redump.api import extract
from redump.extractors import available_backends
from redump.extractors.base import ExtractorError, FileFormat, Operation

log = logging.getLogger("redump")

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redump",
        description="Disassemble or decompile every function in a binary "
        "using a pluggable backend (IDA, radare2, Ghidra, dncil).",
        formatter_class=RichHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="fmt",
        default="auto",
        choices=["auto", *[f.value for f in FileFormat]],
        help="override the auto-detected file format",
    )
    parser.add_argument(
        "-b",
        "--backend",
        required=True,
        choices=available_backends(),
        help="backend to use",
    )
    parser.add_argument(
        "-m",
        "--mode",
        default="decompile",
        choices=[op.value for op in Operation],
        help="operation to run (default: decompile)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="output file (default: <binary>.<backend>.<mode>.<ext>)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    parser.add_argument(
        "binary",
        type=Path,
        metavar="BINARY",
        help="path to the binary to analyze",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    binary: Path = args.binary
    if not binary.is_file():
        log.error("binary not found: %s", binary)
        return 2

    try:
        with console.status(
            "[bold cyan]Preparing analysis...[/bold cyan]",
            spinner="dots",
        ) as status:
            result = extract(
                binary,
                backend=args.backend,
                operation=args.mode,
                file_format=args.fmt,
                progress=lambda message: status.update(
                    f"[bold cyan]{message}[/bold cyan]"
                ),
            )
            status.update("[bold cyan]Writing output...[/bold cyan]")
            output = result.write(args.output)
    except ExtractorError as err:
        console.print(f"[red]Error:[/red] {err}")
        return 1

    log.info("detected format: %s", result.file_format.value)
    console.print(
        f"[green]Extracted {result.function_count} functions to[/green] {output}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
