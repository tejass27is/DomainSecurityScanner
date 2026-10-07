import json
from importlib.metadata import PackageNotFoundError
from urllib.error import URLError

import pytest

from app.api.admin import semgrep_status


class MockResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def mock_pypi(monkeypatch, latest_version="1.200.0"):
    monkeypatch.setattr(
        semgrep_status,
        "urlopen",
        lambda *_args, **_kwargs: MockResponse(
            {"info": {"version": latest_version}}
        ),
    )


def test_semgrep_status_reports_update_available(monkeypatch):
    monkeypatch.setattr(semgrep_status, "version", lambda _package: "1.177.0")
    mock_pypi(monkeypatch)

    result = semgrep_status.get_semgrep_version_status()

    assert result["installed_version"] == "1.177.0"
    assert result["latest_version"] == "1.200.0"
    assert result["update_available"] is True
    assert result["checked_at"]


def test_semgrep_status_reports_up_to_date(monkeypatch):
    monkeypatch.setattr(semgrep_status, "version", lambda _package: "1.200.0")
    mock_pypi(monkeypatch, latest_version="1.200.0")

    result = semgrep_status.get_semgrep_version_status()

    assert result["update_available"] is False


def test_semgrep_status_handles_package_not_installed(monkeypatch):
    def missing_package(_package):
        raise PackageNotFoundError("semgrep")

    monkeypatch.setattr(semgrep_status, "version", missing_package)
    mock_pypi(monkeypatch)

    result = semgrep_status.get_semgrep_version_status()

    assert result["installed_version"] is None
    assert result["update_available"] is None


def test_semgrep_status_reports_pypi_unavailable(monkeypatch):
    monkeypatch.setattr(semgrep_status, "version", lambda _package: "1.177.0")

    def unavailable(*_args, **_kwargs):
        raise URLError("offline")

    monkeypatch.setattr(semgrep_status, "urlopen", unavailable)

    with pytest.raises(semgrep_status.SemgrepVersionCheckError, match="Could not check PyPI"):
        semgrep_status.get_semgrep_version_status()


def test_semgrep_status_rejects_invalid_pypi_response(monkeypatch):
    monkeypatch.setattr(semgrep_status, "version", lambda _package: "1.177.0")
    monkeypatch.setattr(
        semgrep_status,
        "urlopen",
        lambda *_args, **_kwargs: MockResponse({"info": {}}),
    )

    with pytest.raises(semgrep_status.SemgrepVersionCheckError, match="invalid Semgrep version"):
        semgrep_status.get_semgrep_version_status()
