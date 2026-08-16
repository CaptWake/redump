"""High-level Python API for extracting every function from a binary."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from redump.extractors import detect_format, resolve
from redump.extractors.base import (
    ExtractedFunction,
    ExtractorError,
    FileFormat,
    Operation,
)
from redump.output import output_extension, render_functions, write_functions

ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class ExtractionResult:
    """Complete, backend-neutral result of extracting one binary."""

    binary: Path
    backend: str
    operation: Operation
    file_format: FileFormat
    functions: tuple[ExtractedFunction, ...]

    @property
    def function_count(self) -> int:
        return len(self.functions)

    @property
    def text(self) -> str:
        """Render all functions in redump's marker-delimited format."""
        return render_functions(self.functions)

    @property
    def default_output_path(self) -> Path:
        extension = output_extension(self.operation, self.file_format)
        filename = (
            f"{self.binary.name}.{self.backend}.{self.operation.value}{extension}"
        )
        return self.binary.with_name(filename)

    def write(self, output: str | Path | None = None) -> Path:
        """Write the result atomically and return the destination path."""
        destination = (
            Path(output).expanduser()
            if output is not None
            else self.default_output_path
        )
        write_functions(self.functions, destination)
        return destination


def _operation(value: Operation | str) -> Operation:
    try:
        return Operation(value)
    except ValueError as err:
        choices = ", ".join(item.value for item in Operation)
        raise ExtractorError(
            f"unknown operation {value!r}; choose one of: {choices}"
        ) from err


def _format(value: FileFormat | str | None, binary: Path) -> FileFormat:
    if value is None or value == "auto":
        return detect_format(binary)
    try:
        return FileFormat(value)
    except ValueError as err:
        choices = ", ".join(item.value for item in FileFormat)
        raise ExtractorError(
            f"unknown file format {value!r}; choose one of: {choices}"
        ) from err


def _notify(progress: ProgressCallback | None, message: str) -> None:
    if progress is not None:
        progress(message)


def extract(
    binary: str | Path,
    *,
    backend: str,
    operation: Operation | str = Operation.DECOMPILE,
    file_format: FileFormat | str | None = None,
    progress: ProgressCallback | None = None,
) -> ExtractionResult:
    """Extract all renderable functions from ``binary``.

    Args:
        binary: File to inspect.
        backend: Backend name.
        operation: ``decompile`` or ``disassemble``.
        file_format: Explicit format, or ``None``/``auto`` to detect it.
        progress: Optional callback receiving human-readable phase updates.

    Raises:
        ExtractorError: If input validation, format detection, backend startup,
            or extraction fails, or if no functions can be rendered.
    """
    path = Path(binary).expanduser()
    if not path.is_file():
        raise ExtractorError(f"binary not found or not a regular file: {path}")
    path = path.resolve()

    selected_operation = _operation(operation)
    _notify(progress, "Detecting binary format...")
    selected_format = _format(file_format, path)
    _notify(progress, f"Initializing {backend} backend...")
    extractor = resolve(
        backend,
        path,
        fmt=selected_format,
        operation=selected_operation,
    )

    _notify(progress, "Extracting functions...")
    try:
        with extractor as active_extractor:
            functions = tuple(active_extractor.extract_all(selected_operation))
    except ExtractorError:
        raise
    except Exception as err:
        raise ExtractorError(f"{extractor.name} extraction failed: {err}") from err

    if not functions:
        raise ExtractorError("no functions were extracted")
    return ExtractionResult(
        binary=path,
        backend=extractor.name,
        operation=selected_operation,
        file_format=selected_format,
        functions=functions,
    )
