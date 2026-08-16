"""Backends, the registry, and the (format, backend, operation) resolver.

Importing a backend *class* is cheap: the heavy, tool-specific imports are all
deferred to each backend's ``open()``. So this module imports on any machine
even when only one tool is installed.
"""

from __future__ import annotations

from pathlib import Path

from redump.extractors.base import (
    ExtractedFunction,
    Extractor,
    ExtractorError,
    FileFormat,
    FunctionInfo,
    Location,
    Operation,
    Token,
    VirtualAddress,
)
from redump.extractors.dotnet import DotnetExtractor
from redump.extractors.formats import detect_format
from redump.extractors.ghidra import GhidraExtractor
from redump.extractors.ida import IdaExtractor
from redump.extractors.radare2 import Radare2Extractor

#: Canonical backend name -> extractor class.
BACKENDS: dict[str, type[Extractor]] = {
    "ida": IdaExtractor,
    "radare2": Radare2Extractor,
    "ghidra": GhidraExtractor,
    "dncil": DotnetExtractor,
}


def available_backends() -> list[str]:
    """Return the sorted list of selectable backend names."""
    return sorted(BACKENDS)


def backends_for(fmt: FileFormat, operation: Operation | None = None) -> list[str]:
    """Canonical backends that handle ``fmt`` (and ``operation`` if given)."""
    return sorted(
        name
        for name, cls in BACKENDS.items()
        if fmt in cls.formats and (operation is None or operation in cls.operations)
    )


def get_extractor(backend: str, path: Path) -> Extractor:
    """Instantiate the extractor for ``backend`` (no capability checks).

    Raises:
        ExtractorError: if ``backend`` is not a known name.
    """
    try:
        cls = BACKENDS[backend]
    except KeyError as err:
        known = ", ".join(available_backends())
        raise ExtractorError(
            f"unknown backend {backend!r}; choose one of: {known}"
        ) from err
    return cls(path)


def resolve(
    backend: str, path: Path, *, fmt: FileFormat, operation: Operation
) -> Extractor:
    """Build an extractor, validating it can handle ``fmt`` and ``operation``.

    Raises:
        ExtractorError: on an unknown backend, or an unsupported
            (backend, format) / (backend, operation) combination, with a
            message pointing at backends that *can* do the job.
    """
    extractor = get_extractor(backend, path)

    if fmt not in extractor.formats:
        alt = backends_for(fmt, operation)
        hint = f"; try: {', '.join(alt)}" if alt else ""
        raise ExtractorError(
            f"backend {backend!r} does not support {fmt.value} files{hint}"
        )
    if operation not in extractor.operations:
        alt = backends_for(fmt, operation)
        hint = f"; try: {', '.join(alt)}" if alt else ""
        raise ExtractorError(
            f"backend {backend!r} cannot {operation.value} {fmt.value} files{hint}"
        )
    return extractor


__all__ = [
    "BACKENDS",
    "DotnetExtractor",
    "ExtractedFunction",
    "Extractor",
    "ExtractorError",
    "FileFormat",
    "FunctionInfo",
    "GhidraExtractor",
    "IdaExtractor",
    "Location",
    "Operation",
    "Radare2Extractor",
    "Token",
    "VirtualAddress",
    "available_backends",
    "backends_for",
    "detect_format",
    "get_extractor",
    "resolve",
]
