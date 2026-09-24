import io
import os
import zipfile

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi import HTTPException

from app.api.webscan.routes import _authenticated_clone_url, _compute_risk_score, _safe_extract_zip
from app.api.webscan.schemas import WebScanCreateRequest


def test_webscan_create_request_supports_static_and_dynamic_modes():
    dynamic = WebScanCreateRequest(
        mode="dynamic",
        url="https://example.com",
        scan_profile="Full Scan",
        criticality="high",
        authentication_required=True,
        auth_details="username: admin@example.com",
        login_sequence="Open /login and submit creds",
    )
    static = WebScanCreateRequest(mode="static", url="https://github.com/semgrep/semgrep.git", branch="main")

    assert dynamic.mode == "dynamic"
    assert dynamic.scan_profile == "Full Scan"
    assert dynamic.criticality == "high"
    assert dynamic.authentication_required is True
    assert dynamic.auth_details == "username: admin@example.com"
    assert dynamic.login_sequence == "Open /login and submit creds"
    assert static.mode == "static"
    assert static.url == "https://github.com/semgrep/semgrep.git"
    assert static.branch == "main"


def test_static_request_accepts_private_repository_token():
    request = WebScanCreateRequest(
        mode="static",
        url="https://github.com/acme/private-repo.git",
        branch="develop",
        repo_visibility="private",
        repo_token="ghp_example",
    )

    assert request.repo_visibility == "private"
    assert request.repo_token == "ghp_example"


def test_static_request_defaults_to_public_visibility():
    request = WebScanCreateRequest(mode="static", url="https://github.com/acme/public-repo.git")

    assert request.repo_visibility is None
    assert request.repo_token is None


# ─── Private-repo clone URL ───────────────────────────────────────────────────


def test_authenticated_clone_url_injects_token_as_username():
    url = _authenticated_clone_url("https://github.com/acme/private.git", "ghp_secret")

    assert url == "https://x-access-token:ghp_secret@github.com/acme/private.git"


def test_authenticated_clone_url_preserves_port_and_is_a_noop_without_token():
    assert (
        _authenticated_clone_url("https://git.example.com:8443/acme/repo.git", "tok")
        == "https://x-access-token:tok@git.example.com:8443/acme/repo.git"
    )
    assert (
        _authenticated_clone_url("https://github.com/acme/public.git", "")
        == "https://github.com/acme/public.git"
    )


def test_authenticated_clone_url_encodes_special_characters():
    url = _authenticated_clone_url("https://github.com/acme/private.git", "a b/c+d")

    assert url.startswith("https://x-access-token:a%20b%2Fc%2Bd@github.com/")


# ─── ZIP extraction safety ────────────────────────────────────────────────────


def _zip_bytes(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_risk_score_is_bounded_to_100_for_many_findings():
    findings = (
        [{"severity": "critical"} for _ in range(10)]
        + [{"severity": "high"} for _ in range(112)]
        + [{"severity": "info"} for _ in range(50)]
    )
    score = _compute_risk_score(findings)
    assert 0 <= score <= 100
    assert score == 94


def test_risk_score_follows_worst_severity_and_density():
    assert _compute_risk_score([]) == 0
    assert _compute_risk_score([{"severity": "info"}]) == 0
    assert _compute_risk_score([{"severity": "critical"}]) == 100
    assert _compute_risk_score([{"severity": "medium"}]) == 56
    assert _compute_risk_score([{"severity": "low"}, {"severity": "info"}]) == 23


def test_safe_extract_zip_extracts_a_normal_archive(tmp_path):
    payload = _zip_bytes({"src/app.py": "print('hi')"})

    _safe_extract_zip(payload, str(tmp_path))

    assert (tmp_path / "src" / "app.py").read_text() == "print('hi')"


def test_safe_extract_zip_rejects_path_traversal(tmp_path):
    payload = _zip_bytes({"../escape.txt": "x"})

    with pytest.raises(HTTPException):
        _safe_extract_zip(payload, str(tmp_path))

    assert not (tmp_path.parent / "escape.txt").exists()


def test_safe_extract_zip_rejects_absolute_paths(tmp_path):
    payload = _zip_bytes({"/etc/passwd": "x"})

    with pytest.raises(HTTPException):
        _safe_extract_zip(payload, str(tmp_path))


def test_safe_extract_zip_rejects_non_zip_payloads(tmp_path):
    with pytest.raises(HTTPException):
        _safe_extract_zip(b"this is not a zip file", str(tmp_path))
