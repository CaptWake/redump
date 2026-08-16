"""Backend-agnostic extraction interface and core data types.

Mirrors capa's ``FeatureExtractor`` hierarchy: one abstract :class:`Extractor`
defines the contract, each tool ships a concrete subclass under
``redump.extractors``, and the rest of the program talks only to the ABC.

An extractor can do more than one *operation* (disassemble, decompile). Rather
than separate class trees, a single extractor exposes both methods and declares
which it supports via :attr:`Extractor.operations` -- so e.g. the .NET/dncil
backend advertises ``{DISASSEMBLE}`` only and an invalid request is rejected up
front. Each backend likewise declares the :class:`FileFormat` set it handles.
"""

from __future__ import annotations

import abc
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Self

log = logging.getLogger(__name__)


class Operation(str, Enum):
    """A way of rendering a function as text."""

    DISASSEMBLE = "disassemble"
    DECOMPILE = "decompile"


class FileFormat(str, Enum):
    """The container/executable format of a sample."""

    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    DOTNET = "dotnet"


# --- function identity -------------------------------------------------------


class Location(abc.ABC):
    """Where a function lives, abstracted over native and managed code.

    Native functions sit at a virtual address; .NET methods are referred to by
    a metadata token. Both reduce to an ``int`` handle the backend understands,
    plus a way to render that handle for humans.
    """

    value: int  # numeric handle (VA or token); provided by subclasses

    @abc.abstractmethod
    def display(self) -> str:
        """Render the location for the output marker."""

    def __str__(self) -> str:
        return self.display()


@dataclass(frozen=True)
class VirtualAddress(Location):
    """A native virtual address, e.g. ``0x401000``."""

    value: int

    def display(self) -> str:
        return f"{self.value:#x}"


@dataclass(frozen=True)
class Token(Location):
    """A .NET metadata token, e.g. ``0x06000001`` (MethodDef rid 1)."""

    value: int

    def display(self) -> str:
        # .NET tokens are 4 bytes: a 1-byte table id + 3-byte row id.
        return f"{self.value:#010x}"


@dataclass(frozen=True)
class FunctionInfo:
    """A backend-neutral handle to one function."""

    name: str
    location: Location


@dataclass(frozen=True)
class ExtractedFunction:
    """A function plus the text produced for it by some operation."""

    info: FunctionInfo
    code: str
    operation: Operation


class ExtractorError(Exception):
    """Raised when a backend can't load a sample or render a function.

    Backends translate their native, tool-specific exceptions into this type so
    callers can handle failures uniformly.
    """


# --- the extractor contract --------------------------------------------------


class Extractor(abc.ABC):
    """Abstract base for a backend.

    Subclasses own the lifetime of an underlying tool and are context managers.
    They declare their capabilities with the :attr:`formats` and
    :attr:`operations` class attributes, and implement only the operations they
    support (the base :meth:`disassemble`/:meth:`decompile` raise).
    """

    #: Short backend identifier, e.g. ``"radare2"``. Set by each subclass.
    name: str = "base"
    #: File formats this backend can load.
    formats: frozenset[FileFormat] = frozenset()
    #: Operations this backend can perform.
    operations: frozenset[Operation] = frozenset()

    def __init__(self, path: Path) -> None:
        self.path = path

    # --- lifecycle ---------------------------------------------------------

    @abc.abstractmethod
    def open(self) -> None:
        """Load the sample and start the backend. Invoked by ``__enter__``."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release all backend resources. Invoked by ``__exit__``."""

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except Exception as err:
            if exc is not None:
                log.warning(
                    "%s cleanup failed while handling another error: %s",
                    self.name,
                    err,
                )
                return
            if isinstance(err, ExtractorError):
                raise
            raise ExtractorError(f"{self.name} cleanup failed: {err}") from err

    # --- discovery ---------------------------------------------------------

    @abc.abstractmethod
    def get_functions(self) -> Iterator[FunctionInfo]:
        """Yield every function discovered in the sample."""

    # --- operations (override the ones you support) ------------------------

    def disassemble(self, func: FunctionInfo) -> str:
        raise ExtractorError(f"{self.name} does not support disassembly")

    def decompile(self, func: FunctionInfo) -> str:
        raise ExtractorError(f"{self.name} does not support decompilation")

    def supports(self, operation: Operation) -> bool:
        return operation in self.operations

    def extract(self, func: FunctionInfo, operation: Operation) -> str:
        if operation is Operation.DISASSEMBLE:
            return self.disassemble(func)
        if operation is Operation.DECOMPILE:
            return self.decompile(func)
        raise ExtractorError(f"unknown operation: {operation}")

    # --- convenience -------------------------------------------------------

    def extract_all(self, operation: Operation) -> Iterator[ExtractedFunction]:
        """Run ``operation`` over every function, skipping ones that fail.

        A single un-renderable function should never abort the whole run, so
        per-function :class:`ExtractorError` is caught and logged here.
        """
        if not self.supports(operation):
            raise ExtractorError(f"{self.name} does not support {operation.value}")
        for fn in self.get_functions():
            try:
                code = self.extract(fn, operation)
            except ExtractorError as err:
                log.warning("skipping %s @ %s: %s", fn.name, fn.location.display(), err)
                continue
            yield ExtractedFunction(info=fn, code=code, operation=operation)
