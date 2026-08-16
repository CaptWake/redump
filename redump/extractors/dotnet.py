""".NET (CIL) disassembly backend, via ``dnfile`` + ``dncil``.

``dnfile`` parses the managed PE and its metadata tables; ``dncil`` parses and
disassembles individual CIL method bodies. A .NET "function" is a ``MethodDef``,
identified by a metadata :class:`~redump.extractors.base.Token`
(``0x06000000 | rid``) and named ``Namespace.Type::Method``.

This backend disassembles only -- decompiling CIL back to C# is a separate
concern (ILSpy/dnSpy) outside dncil's scope. Both imports are deferred to
:meth:`open` so the package imports fine without the ``dotnet`` extra.

Note: the dnfile/dncil calls below follow Mandiant capa's dotnet extractor.
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
    Token,
)

#: MethodDef metadata table id; tokens are ``(table << 24) | rid``.
_METHODDEF_TABLE = 0x06
log = logging.getLogger(__name__)


def _format_cil_instruction(insn: Any, code_start: int) -> str:
    """Render an instruction with offsets relative to the method's IL stream."""
    operand = insn.operand
    operand_type = insn.opcode.operand_type.name
    if operand is None:
        rendered_operand = ""
    elif operand_type in {"InlineBrTarget", "ShortInlineBrTarget"}:
        rendered_operand = f" IL_{int(operand) - code_start:04X}"
    elif operand_type == "InlineSwitch":
        targets = ", ".join(f"IL_{int(item) - code_start:04X}" for item in operand)
        rendered_operand = f" ({targets})"
    else:
        rendered_operand = f" {operand}"

    offset = int(insn.offset) - code_start
    return f"IL_{offset:04X}: {insn.opcode.name}{rendered_operand}"


class DotnetExtractor(Extractor):
    """Disassemble CIL method bodies using dnfile + dncil."""

    name = "dncil"
    formats = frozenset({FileFormat.DOTNET})
    operations = frozenset({Operation.DISASSEMBLE})

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._pe: Any = None
        # token -> MethodDef row, populated by get_functions().
        self._methods: dict[int, Any] = {}
        # method rid -> "Namespace.Type", best-effort.
        self._owners: dict[int, str] = {}

    def open(self) -> None:
        try:
            import dncil  # noqa: F401, PLC0415  (verify the complete extra)
            import dnfile  # noqa: PLC0415  (optional dependency)
        except ImportError as err:  # pragma: no cover - environment dependent
            raise ExtractorError(
                "dnfile/dncil are not installed; run `pip install dnfile dncil`"
            ) from err

        try:
            self._pe = dnfile.dnPE(  # type: ignore[no-untyped-call, unused-ignore]
                str(self.path)
            )
        except Exception as err:  # dnfile raises various parse errors
            raise ExtractorError(f"failed to parse .NET PE: {err}") from err
        if getattr(self._pe, "net", None) is None:
            try:
                self.close()
            except ExtractorError as err:
                log.debug("dncil cleanup after validation failure: %s", err)
            raise ExtractorError("not a .NET assembly (no CLR metadata)")
        self._owners = self._compute_owners()

    def close(self) -> None:
        pe = self._pe
        self._pe = None
        self._methods.clear()
        self._owners.clear()
        if pe is not None:
            try:
                pe.close()
            except Exception as err:
                raise ExtractorError(f"failed to close .NET image: {err}") from err

    def _compute_owners(self) -> dict[int, str]:
        """Map each MethodDef rid to its declaring ``Namespace.Type`` name.

        A TypeDef's ``MethodList`` points at its first method; the type owns
        methods up to the next type's first method. Best-effort: any failure
        leaves methods un-namespaced rather than aborting.
        """
        owners: dict[int, str] = {}
        try:
            typedefs = list(self._pe.net.mdtables.TypeDef)
            num_methods = self._pe.net.mdtables.MethodDef.num_rows
            for i, td in enumerate(typedefs):
                start = int(td.MethodList.row_index)
                if i + 1 < len(typedefs):
                    end = int(typedefs[i + 1].MethodList.row_index)
                else:
                    end = num_methods + 1
                namespace = str(td.TypeNamespace)
                type_name = str(td.TypeName)
                full = f"{namespace}.{type_name}" if namespace else type_name
                for rid in range(start, end):
                    owners[rid] = full
        except Exception:  # naming is best-effort, never fatal
            return {}
        return owners

    def get_functions(self) -> Iterator[FunctionInfo]:
        try:
            methoddef = self._pe.net.mdtables.MethodDef
            for rid, row in enumerate(methoddef, start=1):
                if int(getattr(row, "Rva", 0)) == 0:
                    continue  # abstract / pinvoke / no IL body
                token = (_METHODDEF_TABLE << 24) | rid
                self._methods[token] = row
                owner = self._owners.get(rid)
                method_name = str(row.Name)
                name = f"{owner}::{method_name}" if owner else method_name
                yield FunctionInfo(name=name, location=Token(token))
        except Exception as err:
            raise ExtractorError(f".NET method discovery failed: {err}") from err

    def disassemble(self, func: FunctionInfo) -> str:
        from dncil.cil.body import CilMethodBody  # noqa: PLC0415
        from dncil.cil.body.reader import (  # noqa: PLC0415
            CilMethodBodyReaderBase,
        )
        from dncil.cil.error import MethodBodyFormatError  # noqa: PLC0415

        row = self._methods.get(func.location.value)
        if row is None:
            raise ExtractorError("unknown method token")

        pe = self._pe
        body_row: Any = row  # narrowing doesn't reach the nested class below

        class _Reader(CilMethodBodyReaderBase):  # type: ignore[misc]
            """Feed method-body bytes from the dnfile-parsed PE to dncil."""

            def __init__(self) -> None:
                self.offset: int = int(pe.get_offset_from_rva(body_row.Rva))

            def read(self, n: int) -> bytes:
                data: bytes = pe.get_data(pe.get_rva_from_offset(self.offset), n)
                self.offset += n
                return data

            def tell(self) -> int:
                return self.offset

            def seek(self, rva: int) -> int:
                self.offset = rva
                return self.offset

        try:
            body = CilMethodBody(_Reader())
            code_start = int(body.offset) + int(body.header_size)
            lines = [
                _format_cil_instruction(insn, code_start) for insn in body.instructions
            ]
            return "\n".join(lines) + "\n"
        except MethodBodyFormatError as err:
            raise ExtractorError(f"malformed CIL body: {err}") from err
        except Exception as err:
            raise ExtractorError(f"CIL disassembly failed: {err}") from err
