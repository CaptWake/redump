"""Serialization of extracted functions to the on-disk marker format.

Each function is preceded by a separator block so the concatenated output can
be split back apart deterministically::

    \\n\\n=====\\nFunction: <name> @ <location>\\n=====\\n<code>

``<location>`` renders as a hex virtual address for native code or a metadata
token for .NET, per the :class:`~redump.extractors.base.Location` subtype.
"""

from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from redump.extractors.base import (
    ExtractedFunction,
    FileFormat,
    Location,
    Operation,
)

log = logging.getLogger(__name__)

#: The rule drawn above and below the function label.
SEPARATOR = "====="


def format_header(name: str, location: Location) -> str:
    """Build the separator block that precedes a function's code."""
    return f"\n\n{SEPARATOR}\nFunction: {name} @ {location.display()}\n{SEPARATOR}\n"


def output_extension(operation: Operation, fmt: FileFormat) -> str:
    """Choose a file extension that reflects the produced content."""
    if operation is Operation.DECOMPILE:
        return ".c"
    if fmt is FileFormat.DOTNET:
        return ".il"  # CIL disassembly
    return ".asm"


def render_functions(functions: Iterable[ExtractedFunction]) -> str:
    """Render functions into the same marker-delimited format used on disk."""
    return "".join(
        format_header(function.info.name, function.info.location) + function.code
        for function in functions
    )


def write_functions(functions: Iterable[ExtractedFunction], out: Path) -> int:
    """Stream ``functions`` to ``out`` and return how many were written.

    Functions are written lazily as they arrive, so a backend that yields one
    rendering at a time never has to hold the whole program in memory.
    """
    count = 0
    out = out.expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=out.parent,
        prefix=f".{out.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        fh = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = -1
        with fh:
            for func in functions:
                fh.write(format_header(func.info.name, func.info.location))
                fh.write(func.code)
                count += 1
        temporary.replace(out)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    log.info("wrote %d function(s) to %s", count, out)
    return count
