import json
import os
from urllib.error import URLError

import pytest

from app.api.admin import prowler_status


class MockResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def mock_pypi(monkeypatch, latest_version="5.45.0"):
    monkeypatch.setattr(
        prowler_status,
        "urlopen",
        lambda *_args, **_kwargs: MockResponse({"info": {"version": latest_version}}),
    )


def test_prowler_status_reports_update_available(monkeypatch):
    monkeypatch.setattr(prowler_status, "_get_installed_prowler_version", lambda: "5.44.0")
    mock_pypi(monkeypatch)

    result = prowler_status.get_prowler_version_status()

    assert result["installed_version"] == "5.44.0"
    assert result["latest_version"] == "5.45.0"
    assert result["update_available"] is True
    assert result["checked_at"]


def test_prowler_status_reports_up_to_date(monkeypatch):
    monkeypatch.setattr(prowler_status, "_get_installed_prowler_version", lambda: "5.45.0")
    mock_pypi(monkeypatch, latest_version="5.45.0")

    result = prowler_status.get_prowler_version_status()

    assert result["update_available"] is False


def test_prowler_status_handles_cli_not_installed(monkeypatch):
    monkeypatch.setattr(prowler_status, "_get_installed_prowler_version", lambda: None)
    mock_pypi(monkeypatch)

    result = prowler_status.get_prowler_version_status()

    assert result["installed_version"] is None
    assert result["update_available"] is None


def test_prowler_status_reports_pypi_unavailable(monkeypatch):
    monkeypatch.setattr(prowler_status, "_get_installed_prowler_version", lambda: "5.44.0")

    def unavailable(*_args, **_kwargs):
        raise URLError("offline")

    monkeypatch.setattr(prowler_status, "urlopen", unavailable)

    with pytest.raises(prowler_status.ProwlerVersionCheckError, match="Could not check PyPI"):
        prowler_status.get_prowler_version_status()


def test_prowler_status_rejects_invalid_pypi_response(monkeypatch):
    monkeypatch.setattr(prowler_status, "_get_installed_prowler_version", lambda: "5.44.0")
    monkeypatch.setattr(
        prowler_status,
        "urlopen",
        lambda *_args, **_kwargs: MockResponse({"info": {}}),
    )

    with pytest.raises(prowler_status.ProwlerVersionCheckError, match="invalid Prowler version"):
        prowler_status.get_prowler_version_status()


def test_prowler_version_lookup_reads_the_isolated_environment(monkeypatch, tmp_path):
    executable = tmp_path / "prowler" / "bin" / "prowler"
    python = executable.with_name("python.exe" if os.name == "nt" else "python")
    executable.parent.mkdir(parents=True)
    executable.touch()
    python.touch()
    monkeypatch.setattr(prowler_status, "PROWLER_EXECUTABLE", str(executable))
    monkeypatch.setattr(prowler_status, "PROWLER_PYTHON_EXECUTABLE", "")
    monkeypatch.setattr(
        prowler_status.shutil,
        "which",
        lambda executable_name: str(executable if executable_name == str(executable) else python)
        if executable_name in {str(executable), str(python)}
        else None,
    )

    class Result:
        returncode = 0
        stdout = "5.44.0\n"
        stderr = ""

    def run(command, **kwargs):
        assert command == [str(python), "-c", prowler_status.PROWLER_VERSION_SCRIPT]
        assert kwargs["timeout"] == 8
        return Result()

    monkeypatch.setattr(prowler_status.subprocess, "run", run)

    assert prowler_status._get_installed_prowler_version() == "5.44.0"


def test_prowler_version_lookup_script_is_valid_python():
    compile(prowler_status.PROWLER_VERSION_SCRIPT, "<prowler-version-check>", "exec")
