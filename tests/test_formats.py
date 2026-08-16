import struct

import pytest
from redump import ExtractorError, FileFormat, detect_format


def make_pe(
    *,
    optional_magic=0x10B,
    optional_size=224,
    directory_count=16,
    clr_rva=0,
    clr_size=0,
):
    pe_offset = 0x80
    optional_start = pe_offset + 24
    directory_offset = 96 if optional_magic == 0x10B else 112
    data = bytearray(optional_start + max(optional_size, directory_offset + 15 * 8))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe_offset + 4 + 16, optional_size)
    struct.pack_into("<H", data, optional_start, optional_magic)
    struct.pack_into("<I", data, optional_start + directory_offset - 4, directory_count)
    struct.pack_into(
        "<II",
        data,
        optional_start + directory_offset + 14 * 8,
        clr_rva,
        clr_size,
    )
    return bytes(data)


@pytest.mark.parametrize(
    "magic",
    [b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"],
)
def test_detects_fat64_macho(tmp_path, magic):
    sample = tmp_path / "sample"
    sample.write_bytes(magic)
    assert detect_format(sample) is FileFormat.MACHO


def test_detects_dotnet_clr_directory(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(make_pe(clr_rva=0x2000, clr_size=0x48))
    assert detect_format(sample) is FileFormat.DOTNET


def test_detects_native_pe_without_clr_directory(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(make_pe())
    assert detect_format(sample) is FileFormat.PE


def test_ignores_clr_bytes_outside_declared_optional_header(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(make_pe(optional_size=96, clr_rva=0x2000, clr_size=0x48))
    assert detect_format(sample) is FileFormat.PE


def test_ignores_clr_directory_not_declared_by_count(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(make_pe(directory_count=14, clr_rva=0x2000, clr_size=0x48))
    assert detect_format(sample) is FileFormat.PE


def test_read_errors_are_normalized(tmp_path):
    with pytest.raises(ExtractorError, match="could not read binary"):
        detect_format(tmp_path / "missing")
