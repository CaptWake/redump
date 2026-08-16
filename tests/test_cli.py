from redump import (
    ExtractedFunction,
    ExtractionResult,
    ExtractorError,
    FileFormat,
    FunctionInfo,
    Operation,
    VirtualAddress,
)
from redump import main as main_module
from rich_argparse import RichHelpFormatter


def test_cli_uses_rich_help_formatter():
    assert main_module.build_parser().formatter_class is RichHelpFormatter


def test_cli_delegates_to_public_api(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")
    output = tmp_path / "output.c"
    result = ExtractionResult(
        binary=binary.resolve(),
        backend="radare2",
        operation=Operation.DECOMPILE,
        file_format=FileFormat.ELF,
        functions=(
            ExtractedFunction(
                FunctionInfo("main", VirtualAddress(0x401000)),
                "int main(void) { return 0; }\n",
                Operation.DECOMPILE,
            ),
        ),
    )

    def fake_extract(path, **kwargs):
        assert path == binary
        assert kwargs["backend"] == "radare2"
        kwargs["progress"]("Testing progress...")
        return result

    monkeypatch.setattr(main_module, "extract", fake_extract)

    assert main_module.main(["-b", "radare2", "-o", str(output), str(binary)]) == 0
    assert "Function: main" in output.read_text(encoding="utf-8")
    assert "Extracted 1 functions" in capsys.readouterr().out


def test_cli_reports_api_failures(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")

    def fail(*args, **kwargs):
        raise ExtractorError("backend unavailable")

    monkeypatch.setattr(main_module, "extract", fail)

    assert main_module.main(["-b", "ida", str(binary)]) == 1
    assert "backend unavailable" in capsys.readouterr().out


def test_cli_rejects_missing_binary(tmp_path):
    assert main_module.main(["-b", "ida", str(tmp_path / "missing")]) == 2
