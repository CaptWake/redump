# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Discovery and activation of IDA Pro's ``idalib`` runtime.

Adapted from Mandiant capa's idalib loader. ``idalib`` ships with IDA Pro but
isn't on ``sys.path`` until activated. When ``import idapro`` fails, this module
reads the location IDA's ``py-activate-idalib.py`` records in the user config,
prepends the idalib Python directory to ``sys.path``, and retries the import.

Adaptations from the original: ``Optional[...]`` -> ``X | None``, a guard for a
missing ``%APPDATA%`` on Windows, a guard for unsupported platforms, and a fix
to ``has_idalib`` so it no longer reports success when no install was found.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

#: Shared-library filename per ``sys.platform``.
_LIBNAMES = {
    "win32": "idalib.dll",
    "linux": "libidalib.so",
    "linux2": "libidalib.so",
    "darwin": "libidalib.dylib",
}


def is_idalib_installed() -> bool:
    """Return True if ``idapro`` is already importable from ``sys.path``."""
    try:
        return importlib.util.find_spec("idapro") is not None
    except ModuleNotFoundError:
        return False


def get_idalib_user_config_path() -> Path | None:
    """Locate IDA's per-user config, following IDA's user-directory rules."""
    # derived from `py-activate-idalib.py` from IDA v9.0 Beta 4
    if sys.platform == "win32":
        # On Windows, use the %APPDATA%\Hex-Rays\IDA Pro directory.
        appdata = os.getenv("APPDATA")
        if appdata is None:
            return None
        config_dir = Path(appdata) / "Hex-Rays" / "IDA Pro"
    else:
        # On macOS and Linux, use ~/.idapro.
        config_dir = Path.home() / ".idapro"

    # The config is now JSON (was INI in older IDA releases).
    user_config_path = config_dir / "ida-config.json"
    if not user_config_path.exists():
        return None
    return user_config_path


def find_idalib() -> Path | None:
    """Return the idalib Python directory, validating the IDA install tree."""
    config_path = get_idalib_user_config_path()
    if not config_path:
        logger.error(
            "IDA Pro user configuration does not exist; "
            "make sure you've installed idalib properly."
        )
        return None

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        ida_install_dir = Path(config["Paths"]["ida-install-dir"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        logger.error(
            "IDA Pro user configuration is invalid or does not contain the "
            "install location; make sure you've installed idalib properly."
        )
        return None

    if not ida_install_dir.exists():
        return None

    libname = _LIBNAMES.get(sys.platform)
    if libname is None:
        logger.error("unsupported platform for idalib: %s", sys.platform)
        return None

    if not (ida_install_dir / "ida.hlp").is_file():
        return None
    if not (ida_install_dir / libname).is_file():
        return None

    idalib_path = ida_install_dir / "idalib" / "python"
    if not idalib_path.exists():
        return None
    if not (idalib_path / "idapro" / "__init__.py").is_file():
        return None

    return idalib_path


def has_idalib() -> bool:
    """Return True if idalib is installed or can be discovered on disk."""
    if is_idalib_installed():
        logger.debug("found installed IDA idalib API")
        return True

    logger.debug("IDA idalib API not installed, searching...")
    idalib_path = find_idalib()
    if idalib_path is None:
        logger.debug("failed to find IDA idalib installation")
        return False

    logger.debug("found IDA idalib API: %s", idalib_path)
    return True


def load_idalib() -> bool:
    """Make ``import idapro`` work, activating idalib from disk if needed.

    Returns True if ``idapro`` is importable afterwards. Safe to call more than
    once; the second import is served from ``sys.modules``.
    """
    try:
        import idapro  # noqa: PLC0415  (probe: is it already on the path?)

        return True
    except ImportError:
        idalib_path = find_idalib()
        if idalib_path is None:
            return False

        path_entry = idalib_path.absolute().as_posix()
        if path_entry not in sys.path:
            sys.path.append(path_entry)
        try:
            import idapro  # noqa: F401, PLC0415

            return True
        except ImportError:
            return False
