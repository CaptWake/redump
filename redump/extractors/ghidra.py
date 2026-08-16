"""Ghidra backend (via ``pyghidra``): disassembly and decompilation.

``pyghidra`` boots a JVM in-process and exposes Ghidra's Java API. Install it
with ``pip install pyghidra`` and set ``GHIDRA_INSTALL_DIR``. All Ghidra/JPype
imports are deferred to :meth:`open`.
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

#: Per-function decompilation timeout, in seconds.
_DECOMPILE_TIMEOUT = 60
log = logging.getLogger(__name__)


class GhidraExtractor(Extractor):
    """Disassemble/decompile functions using Ghidra through pyghidra."""

    name = "ghidra"
    formats = frozenset({FileFormat.PE, FileFormat.ELF, FileFormat.MACHO})
    operations = frozenset({Operation.DISASSEMBLE, Operation.DECOMPILE})

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._cm: Any = None  # the open_program context manager
        self._flat: Any = None  # FlatProgramAPI
        self._program: Any = None
        self._decomp: Any = None
        self._monitor: Any = None
        # address -> Ghidra Function object, populated by get_functions().
        self._cache: dict[int, Any] = {}

    def open(self) -> None:
        try:
            import pyghidra  # noqa: PLC0415  (optional dependency)
        except ImportError as err:  # pragma: no cover - environment dependent
            raise ExtractorError(
                "pyghidra is not installed; run `pip install pyghidra` and set "
                "GHIDRA_INSTALL_DIR"
            ) from err

        try:
            pyghidra.start(verbose=False)  # idempotent: boots the JVM once

            self._cm = pyghidra.open_program(str(self.path))
            self._flat = self._cm.__enter__()
            self._program = self._flat.getCurrentProgram()

            from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
            from ghidra.util.task import ConsoleTaskMonitor  # noqa: PLC0415

            self._monitor = ConsoleTaskMonitor()
            self._decomp = DecompInterface()
            if not self._decomp.openProgram(self._program):
                raise ExtractorError("Ghidra decompiler could not open the program")
        except ExtractorError:
            self._cleanup_after_failed_open()
            raise
        except Exception as err:
            self._cleanup_after_failed_open()
            raise ExtractorError(f"failed to start Ghidra: {err}") from err

    def _cleanup_after_failed_open(self) -> None:
        try:
            self.close()
        except ExtractorError as err:
            log.debug("Ghidra cleanup after startup failure: %s", err)

    def close(self) -> None:
        errors: list[str] = []
        if self._decomp is not None:
            try:
                self._decomp.dispose()
            except Exception as err:
                errors.append(f"decompiler: {err}")
            finally:
                self._decomp = None
        if self._cm is not None:
            try:
                self._cm.__exit__(None, None, None)
            except Exception as err:
                errors.append(f"program: {err}")
            finally:
                self._cm = None
        self._flat = self._program = self._monitor = None
        self._cache.clear()
        if errors:
            raise ExtractorError(f"failed to stop Ghidra ({'; '.join(errors)})")

    def get_functions(self) -> Iterator[FunctionInfo]:
        try:
            manager = self._program.getFunctionManager()
            for func in manager.getFunctions(True):  # True => iterate forward
                address = int(func.getEntryPoint().getOffset())
                self._cache[address] = func
                yield FunctionInfo(
                    name=str(func.getName()), location=VirtualAddress(address)
                )
        except Exception as err:
            raise ExtractorError(f"Ghidra function discovery failed: {err}") from err

    def _function_at(self, address: int) -> Any:
        target = self._cache.get(address)
        if target is not None:
            return target
        space = self._program.getAddressFactory().getDefaultAddressSpace()
        return self._program.getFunctionManager().getFunctionAt(
            space.getAddress(address)
        )

    def disassemble(self, func: FunctionInfo) -> str:
        try:
            target = self._function_at(func.location.value)
            if target is None:
                raise ExtractorError("no function at address")
            listing = self._program.getListing()
            lines = [
                f"{insn.getAddress().getOffset():#x}: {insn}"
                for insn in listing.getInstructions(target.getBody(), True)
            ]
            return "\n".join(lines) + "\n"
        except ExtractorError:
            raise
        except Exception as err:
            raise ExtractorError(f"Ghidra disassembly failed: {err}") from err

    def decompile(self, func: FunctionInfo) -> str:
        try:
            target = self._function_at(func.location.value)
            if target is None:
                raise ExtractorError("no function at address")
            result = self._decomp.decompileFunction(
                target, _DECOMPILE_TIMEOUT, self._monitor
            )
            if not result.decompileCompleted():
                raise ExtractorError(str(result.getErrorMessage()))
            decompiled = result.getDecompiledFunction()
            if decompiled is None:
                raise ExtractorError("Ghidra returned no decompiled function")
            return str(decompiled.getC())
        except ExtractorError:
            raise
        except Exception as err:
            raise ExtractorError(f"Ghidra decompilation failed: {err}") from err
