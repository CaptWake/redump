import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import redump.api as api_module
from redump import (
    Extractor,
    ExtractorError,
    FileFormat,
    FunctionInfo,
    Operation,
    VirtualAddress,
    extract,
)
from redump.extractors import (
    Radare2Extractor,
    get_extractor,
    resolve,
)


class FakeExtractor(Extractor):
    name = "fake"
    formats = frozenset({FileFormat.ELF})
    operations = frozenset({Operation.DECOMPILE})

    def __init__(self, path: Path, *, fail_discovery: bool = False) -> None:
        super().__init__(path)
        self.fail_discovery = fail_discovery
        self.opened = False
        self.closed = False
        self.function_names = ["main", "helper"]

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def get_functions(self):
        if self.fail_discovery:
            raise RuntimeError("SDK failed")
        for index, name in enumerate(self.function_names):
            yield FunctionInfo(name, VirtualAddress(0x401000 + index))

    def decompile(self, func: FunctionInfo) -> str:
        return f"void {func.name}(void) {{}}\n"


def test_extract_returns_public_result(monkeypatch, tmp_path):
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")
    extractor = FakeExtractor(binary.resolve())
    messages = []

    def fake_resolve(backend, path, *, fmt, operation):
        assert (backend, path, fmt, operation) == (
            "fake",
            binary.resolve(),
            FileFormat.ELF,
            Operation.DECOMPILE,
        )
        return extractor

    monkeypatch.setattr(api_module, "resolve", fake_resolve)

    result = extract(
        binary,
        backend="fake",
        file_format="elf",
        progress=messages.append,
    )

    assert extractor.opened and extractor.closed
    assert result.backend == "fake"
    assert result.function_count == 2
    assert "Function: main @ 0x401000" in result.text
    assert result.default_output_path.name == "sample.fake.decompile.c"
    assert messages == [
        "Detecting binary format...",
        "Initializing fake backend...",
        "Extracting functions...",
    ]

    output = result.write(tmp_path / "result.c")
    assert output.read_text(encoding="utf-8") == result.text


def test_extract_rejects_empty_results(monkeypatch, tmp_path):
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")
    extractor = FakeExtractor(binary)
    extractor.function_names = []
    monkeypatch.setattr(api_module, "resolve", lambda *args, **kwargs: extractor)

    with pytest.raises(ExtractorError, match="no functions were extracted"):
        extract(binary, backend="fake", file_format="elf")

    assert extractor.closed


def test_extract_normalizes_unexpected_backend_errors(monkeypatch, tmp_path):
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")
    extractor = FakeExtractor(binary, fail_discovery=True)
    monkeypatch.setattr(api_module, "resolve", lambda *args, **kwargs: extractor)

    with pytest.raises(ExtractorError, match="fake extraction failed: SDK failed"):
        extract(binary, backend="fake", file_format="elf")

    assert extractor.closed


def test_extract_validates_public_string_values(tmp_path):
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")

    with pytest.raises(ExtractorError, match="unknown operation"):
        extract(binary, backend="ida", operation="translate", file_format="elf")
    with pytest.raises(ExtractorError, match="unknown file format"):
        extract(binary, backend="ida", file_format="coff")


@pytest.mark.parametrize("backend", ["r2", "dotnet", "R2", "RADARE2"])
def test_backend_aliases_are_rejected(tmp_path, backend):
    with pytest.raises(ExtractorError, match=f"unknown backend {backend!r}"):
        get_extractor(backend, tmp_path / "sample")


def test_resolver_errors_name_the_backend(tmp_path):
    with pytest.raises(
        ExtractorError,
        match="backend 'dncil' cannot decompile dotnet files",
    ):
        resolve(
            "dncil",
            tmp_path / "sample",
            fmt=FileFormat.DOTNET,
            operation=Operation.DECOMPILE,
        )


def test_radare2_uses_builtin_pdc(monkeypatch, tmp_path):
    commands = []

    def command(value):
        commands.append(value)
        return "int main(void) { return 0; }"

    handle = SimpleNamespace(cmd=command, quit=lambda: None)
    monkeypatch.setitem(
        sys.modules,
        "r2pipe",
        SimpleNamespace(open=lambda *args, **kwargs: handle),
    )
    extractor = Radare2Extractor(tmp_path / "sample")

    with extractor:
        output = extractor.decompile(FunctionInfo("main", VirtualAddress(0x401000)))

    assert output == "int main(void) { return 0; }"
    assert commands == ["aaaa", "pdc @ 4198400"]


def test_radare2_starts_with_diagnostics_silenced(monkeypatch, tmp_path):
    handle = SimpleNamespace(cmd=lambda command: "", quit=lambda: None)
    calls = []

    def fake_open(path, *, flags):
        calls.append((path, flags))
        return handle

    monkeypatch.setitem(sys.modules, "r2pipe", SimpleNamespace(open=fake_open))
    sample = tmp_path / "sample"
    extractor = Radare2Extractor(sample)

    with extractor:
        pass

    assert calls == [(str(sample), ["-2"])]
