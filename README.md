# redump

redump extracts, disassembles, or decompiles every function in a binary and writes the results into a single text file optimized for one-shot analysis by LLMs.

Use it as an installed command or import it as a typed Python package for reverse-engineering workflows, automated triage, and downstream analysis.

* [IDA Pro](https://hex-rays.com/ida-pro) (`ida`)
* [radare2](https://rada.re/n/) (`radare2`)
* [Ghidra](https://github.com/NationalSecurityAgency/ghidra) (`ghidra`)
* [dncil](https://github.com/mandiant/dncil) (`dncil`) for .NET assemblies

redump automatically detects the input format and routes analysis through a backend that supports it.

## Installation

Install the command from [PyPI](https://pypi.org/project/redump/) with the extra
for the backend you intend to use:

```bash
uv tool install "redump[radare2]"
```

Add redump to a Python project with uv or pip:

```bash
uv add "redump[radare2]"
pip install "redump[radare2]"
```

Available extras are `radare2`, `ghidra`, `dotnet`, and `all`. IDA is provided
by the IDA Pro installation and does not have a PyPI extra. For development
against a local checkout:

```bash
uv add --editable "../redump[radare2]"
```

Backend requirements:

| Backend   | Requirements                            |
| --------- | --------------------------------------- |
| `radare2` | radare2 installed and available in PATH |
| `ghidra`  | pyghidra + `GHIDRA_INSTALL_DIR`         |
| `dncil`   | python modules                          |
| `ida`     | IDA Pro with idalib available           |

If `idapro` is not already importable, redump will attempt to locate and activate IDA automatically.

## Usage

### Basic Examples

```bash
# Decompile using radare2
redump -b radare2 ./target.bin

# Disassemble using Ghidra
redump -b ghidra -m disassemble ./target.bin

# .NET / CIL disassembly
redump -b dncil -m disassemble malware.exe

# Force format detection override
redump -f pe -b ida sample.exe

# Custom output file
redump -b ida -o output.c sample.exe
```

### Command Line Options

| Option            | Description                                                        |
| ----------------- | ------------------------------------------------------------------ |
| `BINARY`          | Binary to analyze (required positional argument)                   |
| `-b, --backend`   | Backend to use (`ida`, `radare2`, `ghidra`, `dncil`)               |
| `-m, --mode`      | `decompile` (default) or `disassemble`                             |
| `-f, --format`    | Override format detection (`auto`, `pe`, `elf`, `macho`, `dotnet`) |
| `-o, --output`    | Output file path                                                   |
| `-v, --verbose`   | Enable debug logging                                               |

### Output File Naming

By default:

```text
<binary>.<backend>.<mode>.<ext>
```

Examples:

```text
sample.exe.ida.decompile.c
sample.exe.radare2.disassemble.asm
assembly.dll.dncil.disassemble.il
```

If the selected backend cannot process the detected format, redump exits with a clear error and suggests a compatible backend when possible.

## Python API

`extract()` performs format detection, backend validation, tool startup,
function extraction, and cleanup. It returns an immutable `ExtractionResult`;
it does not write a file unless `write()` is called.

```python
from redump import ExtractorError, extract

try:
    result = extract(
        "sample.exe",
        backend="radare2",
        operation="decompile",
    )
except ExtractorError as error:
    print(f"analysis failed: {error}")
else:
    print(result.file_format.value)
    print(result.function_count)
    print(result.text)
    output = result.write()  # sample.exe.radare2.decompile.c
```

Pass `file_format="pe"` to override detection or a callback such as
`progress=print` to receive phase updates. Individual functions are available
as `result.functions`, and `result.write(path)` atomically replaces a custom
destination. Expected input, capability, backend, and extraction failures are
reported as `ExtractorError`.

## Output Format

Functions are concatenated into a single file and separated by markers:

```text
===== 
Function: <name> @ <location>
=====
<code>
```

Example:

```text
=====
Function: main @ 0x401000
=====
int main(void) {
    return 0;
}
```

Extensions reflect the extracted content:

| Type               | Extension |
| ------------------ | --------- |
| Decompiled code    | `.c`      |
| Native disassembly | `.asm`    |
| .NET IL            | `.il`     |


## Development

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

Tests use mocks and synthetic samples, so reverse-engineering tools are not required to run the test suite.

## Extending

To add a new backend:

1. Create a subclass of `Extractor`.
2. Implement the required operations.
3. Define supported formats and capabilities.
4. Register the backend in `extractors/__init__.py`.

The architecture is intentionally similar to capa's plugin model, making new backends straightforward to integrate.
