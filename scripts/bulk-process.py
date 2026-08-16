from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
import multiprocessing.pool
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from redump.api import extract
from redump.extractors import available_backends
from redump.extractors.base import ExtractorError, FileFormat, Operation
from redump.output import output_extension

logger = logging.getLogger("redump.bulk")


@dataclass(frozen=True)
class BulkTask:
    sample: str
    backend: str
    output_dir: str | None
    input_dir: str
    operation: str
    fmt: str  # "auto" or a FileFormat value
    log_level: int


class _ResultBase(TypedDict):
    path: str
    status: str  # "ok" | "error"


class SampleResult(_ResultBase, total=False):
    error: str
    output: str
    functions: int
    format: str


def _output_path(
    sample: Path,
    input_dir: Path,
    output_dir: Path | None,
    backend: str,
    operation: Operation,
    fmt: FileFormat,
) -> Path:
    suffix = f".{backend}.{operation.value}{output_extension(operation, fmt)}"
    if output_dir is None:
        return sample.with_name(sample.name + suffix)
    target = output_dir / sample.relative_to(input_dir)  # mirror the tree
    return target.with_name(target.name + suffix)


def process_sample(task: BulkTask) -> SampleResult:
    """Process one sample. Never raises: failures return ``status=error``."""
    logging.basicConfig(
        level=task.log_level, format="%(levelname)s %(name)s: %(message)s"
    )
    sample = Path(task.sample)
    operation = Operation(task.operation)
    try:
        result = extract(
            sample,
            backend=task.backend,
            operation=operation,
            file_format=task.fmt,
        )
        output = _output_path(
            sample,
            Path(task.input_dir),
            Path(task.output_dir) if task.output_dir else None,
            result.backend,
            operation,
            result.file_format,
        )
        result.write(output)
    except ExtractorError as err:
        return {"path": task.sample, "status": "error", "error": str(err)}
    except Exception as err:  # last resort: keep the batch alive
        return {
            "path": task.sample,
            "status": "error",
            "error": f"unexpected error: {err}",
        }

    return {
        "path": task.sample,
        "status": "ok",
        "output": str(output),
        "functions": result.function_count,
        "format": result.file_format.value,
    }


def _iter_samples(input_dir: Path, pattern: str) -> Iterator[Path]:
    """Yield regular files under ``input_dir`` matching ``pattern`` (rglob)."""
    for path in sorted(input_dir.rglob(pattern)):
        if not path.is_file():
            continue
        if path.suffix in {".c", ".asm", ".il"}:
            continue  # don't reprocess our own outputs
        yield path


def _map_results(
    tasks: list[BulkTask],
    *,
    use_mp: bool,
    parallelism: int,
    max_tasks_per_child: int | None,
) -> Iterator[SampleResult]:
    if not use_mp:
        if parallelism <= 1:
            for task in tasks:
                yield process_sample(task)
            return
        with multiprocessing.pool.ThreadPool(parallelism) as pool:
            yield from pool.imap_unordered(process_sample, tasks)
        return

    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=parallelism, maxtasksperchild=max_tasks_per_child) as pool:
        yield from pool.imap_unordered(process_sample, tasks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redump-bulk",
        description="Disassemble/decompile every sample in a directory.",
    )
    parser.add_argument(
        "input_directory", type=Path, help="directory of samples to recurse"
    )
    parser.add_argument(
        "-b",
        "--backend",
        required=True,
        metavar="BACKEND",
        help=f"backend; one of: {', '.join(available_backends())}",
    )
    parser.add_argument(
        "-m",
        "--mode",
        default="decompile",
        choices=[op.value for op in Operation],
        help="operation to run (default: decompile)",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="fmt",
        default="auto",
        choices=["auto", *[f.value for f in FileFormat]],
        help="override the auto-detected file format",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="write outputs here, mirroring the input tree "
        "(default: alongside each sample)",
    )
    parser.add_argument(
        "--pattern",
        default="*",
        help="glob used with rglob to select samples (default: '*')",
    )
    parser.add_argument(
        "-n",
        "--parallelism",
        type=int,
        default=multiprocessing.cpu_count(),
        help="number of workers (default: CPU count)",
    )
    parser.add_argument(
        "--no-mp",
        action="store_true",
        help="use threads (or the current thread if -n 1) instead of processes",
    )
    parser.add_argument(
        "--max-tasks-per-child",
        type=int,
        default=1,
        metavar="N",
        help="recycle each worker after N samples; 0 means never (default 1)",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="debug logs")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="errors and warnings only"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.quiet:
        level = logging.WARNING
    elif args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    input_dir: Path = args.input_directory
    if not input_dir.is_dir():
        logger.error("not a directory: %s", input_dir)
        return 2

    samples = list(_iter_samples(input_dir, args.pattern))
    if not samples:
        logger.warning("no samples matched %r under %s", args.pattern, input_dir)
        return 1

    tasks = [
        BulkTask(
            sample=str(sample),
            backend=args.backend,
            output_dir=str(args.output_dir) if args.output_dir else None,
            input_dir=str(input_dir),
            operation=args.mode,
            fmt=args.fmt,
            log_level=level,
        )
        for sample in samples
    ]

    max_tasks_per_child = args.max_tasks_per_child or None  # 0 -> None
    total = len(tasks)
    succeeded = 0
    results: dict[str, dict[str, object]] = {}

    for i, result in enumerate(
        _map_results(
            tasks,
            use_mp=not args.no_mp,
            parallelism=args.parallelism,
            max_tasks_per_child=max_tasks_per_child,
        ),
        start=1,
    ):
        path = result["path"]
        if result["status"] == "ok":
            succeeded += 1
            logger.info(
                "[%d/%d] ok: %s (%d functions)",
                i,
                total,
                path,
                result.get("functions", 0),
            )
        else:
            logger.warning(
                "[%d/%d] error: %s: %s", i, total, path, result.get("error", "")
            )
        results[path] = {k: v for k, v in result.items() if k != "path"}

    print(json.dumps(results, indent=2))
    logger.info("done: %d/%d succeeded", succeeded, total)
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
