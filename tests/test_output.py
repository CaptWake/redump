import pytest
from redump import (
    ExtractedFunction,
    FunctionInfo,
    Operation,
    VirtualAddress,
)
from redump.output import write_functions


def extracted_function(name="main"):
    return ExtractedFunction(
        FunctionInfo(name, VirtualAddress(0x401000)),
        f"void {name}(void) {{}}\n",
        Operation.DECOMPILE,
    )


def test_write_functions_replaces_destination_atomically(tmp_path):
    output = tmp_path / "nested" / "result.c"
    count = write_functions([extracted_function()], output)

    assert count == 1
    assert "Function: main @ 0x401000" in output.read_text(encoding="utf-8")


def test_write_functions_preserves_existing_file_on_failure(tmp_path):
    output = tmp_path / "result.c"
    output.write_text("previous result", encoding="utf-8")

    def failing_functions():
        yield extracted_function()
        raise RuntimeError("backend failed")

    with pytest.raises(RuntimeError, match="backend failed"):
        write_functions(failing_functions(), output)

    assert output.read_text(encoding="utf-8") == "previous result"
    assert list(tmp_path.glob(".result.c.*.tmp")) == []
