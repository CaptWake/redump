"""radare2 backend (via ``r2pipe``): disassembly and decompilation.

Disassembly uses ``pdf`` (disassemble function). Decompilation uses radare2's
built-in ``pdc`` pseudo-decompiler. The ``r2pipe`` import is deferred to
:meth:`open`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from redump.extractors.base import (
    Extractor,
    ExtractorError,
    FileFormat,
    FunctionInfo,
    Operation,
    VirtualAddress,
)

log = logging.getLogger(__name__)


class Radare2Extractor(Extractor):
    """Disassemble/decompile functions using radare2 + r2pipe."""

    name = "radare2"
    formats = frozenset({FileFormat.PE, FileFormat.ELF, FileFormat.MACHO})
    operations = frozenset({Operation.DISASSEMBLE, Operation.DECOMPILE})

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._r2: Any = None

    def open(self) -> None:
        try:
            import r2pipe  # noqa: PLC0415  (deferred: optional dependency)
        except ImportError as err:  # pragma: no cover - environment dependent
            raise ExtractorError(
                "r2pipe is not installed; run `pip install r2pipe` and ensure "
                "the radare2 binary is on PATH"
            ) from err

        try:
            self._r2 = r2pipe.open(str(self.path), flags=["-2"])
            self._r2.cmd("aaaa")
        except Exception as err:
            try:
                self.close()
            except ExtractorError as cleanup_error:
                log.debug("radare2 cleanup after startup failure: %s", cleanup_error)
            raise ExtractorError(f"failed to start radare2: {err}") from err

    def close(self) -> None:
        r2 = self._r2
        self._r2 = None
        if r2 is not None:
            try:
                r2.quit()
            except Exception as err:
                raise ExtractorError(f"failed to stop radare2: {err}") from err

    def get_functions(self) -> Iterator[FunctionInfo]:
        try:
            functions: list[dict[str, Any]] = self._r2.cmdj("aflj") or []
        except Exception as err:
            raise ExtractorError(f"radare2 function discovery failed: {err}") from err
        for fn in functions:
            try:
                yield FunctionInfo(
                    name=str(fn["name"]),
                    location=VirtualAddress(int(fn["addr"])),
                )
            except (KeyError, TypeError, ValueError) as err:
                raise ExtractorError(
                    f"invalid function record from radare2: {fn!r}"
                ) from err

    def disassemble(self, func: FunctionInfo) -> str:
        try:
            out: str = self._r2.cmd(f"pdf @ {func.location.value}")
        except Exception as err:
            raise ExtractorError(f"radare2 disassembly failed: {err}") from err
        if not out.strip():
            raise ExtractorError("`pdf` produced no output")
        return out

    def decompile(self, func: FunctionInfo) -> str:
        try:
            out: str = self._r2.cmd(f"pdc @ {func.location.value}")
        except Exception as err:
            raise ExtractorError(f"radare2 decompilation failed: {err}") from err
        if not out.strip():
            raise ExtractorError("`pdc` produced no output")
        return out
