"""IDA Pro backend (via headless ``idalib``): disassembly and decompilation.

Requires a licensed IDA Pro (>= 9.0); decompilation additionally requires the
Hex-Rays decompiler. If ``import idapro`` doesn't resolve directly,
:func:`load_idalib` discovers the install and activates it. All IDA imports are
deferred and failures surface as :class:`ExtractorError`.
"""

from __future__ import annotations

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
from redump.utils.idalib import load_idalib


class IdaExtractor(Extractor):
    """Disassemble/decompile functions using IDA Pro."""

    name = "ida"
    formats = frozenset({FileFormat.PE, FileFormat.ELF, FileFormat.MACHO})
    operations = frozenset({Operation.DISASSEMBLE, Operation.DECOMPILE})

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._open = False

    def open(self) -> None:
        if not load_idalib():
            raise ExtractorError(
                "could not activate idalib; install IDA Pro >= 9.0 and run its "
                "`py-activate-idalib.py`, or otherwise make `import idapro` work"
            )

        import idapro  # noqa: PLC0415  (importable via load_idalib)

        try:
            rc = idapro.open_database(str(self.path), run_auto_analysis=True)
        except Exception as err:
            raise ExtractorError(f"failed to open IDA database: {err}") from err
        if rc != 0:
            raise ExtractorError(f"idapro.open_database failed (rc={rc})")
        self._open = True

    def close(self) -> None:
        if self._open:
            import idapro  # noqa: PLC0415

            idapro.close_database(save=False)
            self._open = False

    def get_functions(self) -> Iterator[FunctionInfo]:
        try:
            import ida_funcs  # noqa: PLC0415
            import idautils  # noqa: PLC0415

            for ea in idautils.Functions():
                func = ida_funcs.get_func(ea)
                name = ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
                start = int(func.start_ea) if func is not None else int(ea)
                yield FunctionInfo(name=str(name), location=VirtualAddress(start))
        except Exception as err:
            raise ExtractorError(f"IDA function discovery failed: {err}") from err

    def disassemble(self, func: FunctionInfo) -> str:
        try:
            import ida_funcs  # noqa: PLC0415
            import idautils  # noqa: PLC0415
            import idc  # noqa: PLC0415

            start = func.location.value
            f: Any = ida_funcs.get_func(start)
            if f is None:
                raise ExtractorError("no function at address")
            lines = [
                f"{ea:#x}: {idc.GetDisasm(ea)}"
                for ea in idautils.Heads(f.start_ea, f.end_ea)
            ]
            return "\n".join(lines) + "\n"
        except ExtractorError:
            raise
        except Exception as err:
            raise ExtractorError(f"IDA disassembly failed: {err}") from err

    def decompile(self, func: FunctionInfo) -> str:
        try:
            import ida_hexrays  # noqa: PLC0415

            if not ida_hexrays.init_hexrays_plugin():
                raise ExtractorError("the Hex-Rays decompiler is not available")
            cfunc: Any = ida_hexrays.decompile(func.location.value)
        except ExtractorError:
            raise
        except Exception as err:  # Hex-Rays raises DecompilationFailure et al.
            raise ExtractorError(f"IDA decompilation failed: {err}") from err
        if cfunc is None:
            raise ExtractorError("Hex-Rays returned no pseudocode")
        return str(cfunc)
