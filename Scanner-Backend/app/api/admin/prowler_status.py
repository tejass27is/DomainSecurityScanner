import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)
PROWLER_EXECUTABLE = os.getenv("PROWLER_EXECUTABLE", "/opt/prowler/bin/prowler").strip()
PROWLER_PYTHON_EXECUTABLE = os.getenv("PROWLER_PYTHON_EXECUTABLE", "").strip()
PROWLER_VERSION_SCRIPT = (
    "from importlib.metadata import PackageNotFoundError, version\n"
    "try:\n    print(version('prowler'))\n"
    "except PackageNotFoundError:\n    print('NOT_INSTALLED')"
)


class ProwlerVersionCheckError(RuntimeError):
    pass


def _get_installed_prowler_version() -> str | None:
    prowler_path = shutil.which(PROWLER_EXECUTABLE)
    if prowler_path is None:
        return None

    python_executable = PROWLER_PYTHON_EXECUTABLE
    if not python_executable:
        python_name = "python.exe" if os.name == "nt" else "python"
        python_executable = os.path.join(os.path.dirname(prowler_path), python_name)
    python_path = shutil.which(python_executable)
    if python_path is None:
        raise ProwlerVersionCheckError(
            "Prowler is installed, but its Python environment could not be located."
        )

    try:
        result = subprocess.run(
            [python_path, "-c", PROWLER_VERSION_SCRIPT],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Could not read the installed Prowler version: %s", exc)
        raise ProwlerVersionCheckError(
            "Could not read the Prowler version installed in the scanner environment."
        ) from exc

    installed_version = result.stdout.strip()
    if result.returncode != 0:
        logger.warning("Prowler version lookup failed: %s", result.stderr.strip())
        raise ProwlerVersionCheckError(
            "Could not read the Prowler version installed in the scanner environment."
        )
    if installed_version == "NOT_INSTALLED":
        return None
    if not installed_version:
        raise ProwlerVersionCheckError(
            "The Prowler environment returned an invalid version response."
        )
    return installed_version


def get_prowler_version_status() -> dict:
    installed_version = _get_installed_prowler_version()
    request = Request(
        "https://pypi.org/pypi/prowler/json",
        headers={"Accept": "application/json", "User-Agent": "DomainSecurityScanner"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            package_info = json.load(response)
    except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("Could not retrieve Prowler release information from PyPI: %s", exc)
        raise ProwlerVersionCheckError(
            "Could not check PyPI for Prowler updates. Check the backend's internet connection and try again."
        ) from exc

    info = package_info.get("info") if isinstance(package_info, dict) else None
    latest_version = info.get("version") if isinstance(info, dict) else None
    if not isinstance(latest_version, str) or not latest_version.strip():
        raise ProwlerVersionCheckError("PyPI returned an invalid Prowler version response.")

    return {
        "installed_version": installed_version,
        "latest_version": latest_version,
        "update_available": (
            installed_version != latest_version if installed_version is not None else None
        ),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
