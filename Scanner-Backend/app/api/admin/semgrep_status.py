import json
import logging
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class SemgrepVersionCheckError(RuntimeError):
    pass


def get_semgrep_version_status() -> dict:
    try:
        installed_version = version("semgrep")
    except PackageNotFoundError:
        installed_version = None

    request = Request(
        "https://pypi.org/pypi/semgrep/json",
        headers={"Accept": "application/json", "User-Agent": "DomainSecurityScanner"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            package_info = json.load(response)
    except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("Could not retrieve Semgrep release information from PyPI: %s", exc)
        raise SemgrepVersionCheckError(
            "Could not check PyPI for Semgrep updates. Check the backend's internet connection and try again."
        ) from exc

    info = package_info.get("info") if isinstance(package_info, dict) else None
    latest_version = info.get("version") if isinstance(info, dict) else None
    if not isinstance(latest_version, str) or not latest_version.strip():
        raise SemgrepVersionCheckError("PyPI returned an invalid Semgrep version response.")

    return {
        "installed_version": installed_version,
        "latest_version": latest_version,
        "update_available": (
            installed_version != latest_version if installed_version is not None else None
        ),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
