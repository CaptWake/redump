"""Lightweight file-format detection.

Sniffs magic bytes (and, for PE, the CLR data directory) to classify a sample
as ELF, Mach-O, native PE, or .NET -- without pulling in pefile/dnfile, so
detection works even when the optional backends aren't installed.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO

from redump.extractors.base import ExtractorError, FileFormat

_MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",  # 32-bit
        b"\xce\xfa\xed\xfe",  # 32-bit, byte-swapped
        b"\xfe\xed\xfa\xcf",  # 64-bit
        b"\xcf\xfa\xed\xfe",  # 64-bit, byte-swapped
        b"\xca\xfe\xba\xbe",  # fat/universal
        b"\xbe\xba\xfe\xca",  # fat, byte-swapped
        b"\xca\xfe\xba\xbf",  # fat/universal, 64-bit
        b"\xbf\xba\xfe\xca",  # fat 64-bit, byte-swapped
    }
)

#: Index of the CLR runtime header in the PE optional-header data directory.
_CLR_DIRECTORY_INDEX = 14


def _is_dotnet(fh: BinaryIO) -> bool:
    """Return True if a PE has a non-empty CLR header directory (i.e. .NET)."""
    try:
        fh.seek(0x3C)
        (e_lfanew,) = struct.unpack("<I", fh.read(4))
        fh.seek(e_lfanew)
        if fh.read(4) != b"PE\x00\x00":
            return False

        coff = fh.read(20)
        if len(coff) < 20:
            return False
        (size_optional,) = struct.unpack_from("<H", coff, 16)
        if size_optional == 0:
            return False

        (opt_magic,) = struct.unpack("<H", fh.read(2))
        # Data directories begin 96 bytes into a PE32 optional header, 112 into
        # a PE32+ one.
        if opt_magic == 0x10B:
            dir_offset = 96
        elif opt_magic == 0x20B:
            dir_offset = 112
        else:
            return False

        required_size = dir_offset + (_CLR_DIRECTORY_INDEX + 1) * 8
        if size_optional < required_size:
            return False

        optional_start = e_lfanew + 4 + 20
        fh.seek(optional_start + dir_offset - 4)
        (directory_count,) = struct.unpack("<I", fh.read(4))
        if directory_count <= _CLR_DIRECTORY_INDEX:
            return False
        fh.seek(optional_start + dir_offset + _CLR_DIRECTORY_INDEX * 8)
        entry = fh.read(8)
        if len(entry) < 8:
            return False
        rva, size = struct.unpack("<II", entry)
    except (struct.error, OSError):
        return False
    return bool(rva != 0 and size != 0)


def detect_format(path: Path) -> FileFormat:
    """Classify ``path`` by its contents.

    Raises:
        ExtractorError: if the format isn't recognized.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
            if head[:4] == b"\x7fELF":
                return FileFormat.ELF
            if head[:4] in _MACHO_MAGICS:
                return FileFormat.MACHO
            if head[:2] == b"MZ":
                return FileFormat.DOTNET if _is_dotnet(fh) else FileFormat.PE
    except OSError as err:
        raise ExtractorError(f"could not read binary {path}: {err}") from err
    raise ExtractorError(f"unrecognized file format: {path}")
