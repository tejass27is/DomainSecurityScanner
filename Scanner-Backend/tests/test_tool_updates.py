import json
from urllib.error import HTTPError

import pytest
from fastapi import HTTPException

from app.api.admin import routes, tool_updates
from app.api.admin.schemas import ToolUpdateRequest


class MockResponse:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_dispatch_tool_update_starts_github_workflow(monkeypatch):
    monkeypatch.setenv("TOOL_UPDATE_GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("TOOL_UPDATE_REPOSITORY", "example/scanner")
    requests = []

    def mock_urlopen(request, timeout):
        requests.append((request, timeout))
        return MockResponse()

    monkeypatch.setattr(tool_updates, "urlopen", mock_urlopen)

    result = tool_updates.dispatch_tool_update("semgrep", "1.181.0")

    request, timeout = requests[0]
    assert request.full_url.endswith(
        "/repos/example/scanner/actions/workflows/backend.yml/dispatches"
    )
    assert request.get_header("Authorization") == "Bearer test-token"
    assert json.loads(request.data) == {
        "ref": "main",
        "inputs": {"tool": "semgrep", "version": "1.181.0"},
    }
    assert timeout == 15
    assert result["status"] == "queued"
    assert result["requested_version"] == "1.181.0"


def test_dispatch_tool_update_requires_backend_token(monkeypatch):
    monkeypatch.delenv("TOOL_UPDATE_GITHUB_TOKEN", raising=False)

    with pytest.raises(tool_updates.ToolUpdateError, match="not configured"):
        tool_updates.dispatch_tool_update("prowler", "5.45.0")


def test_dispatch_tool_update_rejects_unsafe_version(monkeypatch):
    monkeypatch.setenv("TOOL_UPDATE_GITHUB_TOKEN", "test-token")

    with pytest.raises(tool_updates.ToolUpdateError, match="unsupported characters"):
        tool_updates.dispatch_tool_update("semgrep", "1.2.0;malicious")


def test_dispatch_tool_update_reports_github_permission_errors(monkeypatch):
    monkeypatch.setenv("TOOL_UPDATE_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        tool_updates,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            HTTPError("https://api.github.com", 403, "Forbidden", {}, None)
        ),
    )

    with pytest.raises(tool_updates.ToolUpdateError, match="Actions write permission"):
        tool_updates.dispatch_tool_update("prowler", "5.45.0")


def test_start_tool_update_dispatches_only_when_release_is_new(monkeypatch):
    monkeypatch.setattr(
        routes,
        "get_semgrep_version_status",
        lambda: {
            "latest_version": "1.181.0",
            "update_available": True,
        },
    )
    monkeypatch.setattr(
        routes,
        "dispatch_tool_update",
        lambda tool, version: {"tool": tool, "requested_version": version},
    )

    result = routes.start_tool_update(ToolUpdateRequest(tool="semgrep"), object())

    assert result == {"tool": "semgrep", "requested_version": "1.181.0"}


def test_start_tool_update_rejects_when_already_up_to_date(monkeypatch):
    monkeypatch.setattr(
        routes,
        "get_semgrep_version_status",
        lambda: {"latest_version": "1.181.0", "update_available": False},
    )
    monkeypatch.setattr(
        routes,
        "dispatch_tool_update",
        lambda *_args: pytest.fail("Must not dispatch an up-to-date tool"),
    )

    with pytest.raises(HTTPException) as error:
        routes.start_tool_update(ToolUpdateRequest(tool="semgrep"), object())

    assert error.value.status_code == 409
