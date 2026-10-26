import os
from io import BytesIO
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from pypdf import PdfReader

from app.api.webscan.acunetix import (
    AcunetixClient,
    AcunetixError,
    get_scanner_connection_status,
    _error_detail,
    _env_bool,
    _env_float,
    map_criticality,
    resolve_base_url,
)
from app.api.webscan.routes import (
    _brand_neutral_data,
    _brand_neutral_text,
    _build_dynamic_webscan_pdf,
    _build_static_webscan_pdf,
    _report_cwe,
    _report_value,
    _semgrep_payload_to_findings,
)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("ACUNETIX_URL", raising=False)
    monkeypatch.delenv("ACUNETIX_BASE_URL", raising=False)
    monkeypatch.delenv("ACUNETIX_PROFILE_ID", raising=False)


def test_report_missing_values_use_vendor_neutral_text():
    assert _report_value(None) == "Not available"
    assert _report_value("Not provided by Acunetix") == "Not provided by iSecurify"
    assert _brand_neutral_text("ACUNETIX") == "iSecurify"
    assert _brand_neutral_data({"message": "Acunetix scan"}) == {"message": "iSecurify scan"}


def test_scanner_connection_status_reports_missing_configuration():
    status = get_scanner_connection_status()

    assert status["reachable"] is False
    assert status["profiles"] == []
    assert "URL is not configured" in status["error"]


def test_scanner_connection_status_reports_profiles_without_exposing_key(monkeypatch):
    monkeypatch.setenv("ACUNETIX_URL", "https://scanner.example")
    monkeypatch.setenv("ACUNETIX_API_KEY", "secret-key")

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def list_profiles(self):
            return [{"profile_id": "profile-1", "name": "Full Scan"}]

        def resolve_profile_id(self):
            return "profile-1"

    monkeypatch.setattr("app.api.webscan.acunetix.AcunetixClient", FakeClient)
    status = get_scanner_connection_status()

    assert status["reachable"] is True
    assert status["api_key_configured"] is True
    assert "secret-key" not in str(status)
    assert status["profile_name"] == "Full Scan"


def test_report_cwe_is_normalized_for_display():
    assert _report_cwe(89) == "CWE-89"
    assert _report_cwe("CWE-79, 89") == "CWE-79, CWE-89"
    assert _report_cwe({"id": "CWE-538"}) == "CWE-538"
    assert _report_cwe(None) == "Not available"


def test_developer_report_is_branded_and_includes_scan_metadata():
    record = SimpleNamespace(
        severity_distribution={"critical": 1},
        findings=[
            {
                "title": "SQL Injection",
                "severity": 4,
                "severity_label": "critical",
                "cwe": 89,
                "cvss_score": 9.8,
                "confidence": 85,
                "vuln_id": "vuln-1",
                "result_id": "result-1",
                "target_id": "target-1",
                "status": "pending",
                "last_seen": "2026-10-07",
                "port": 443,
                "protocol": "https",
                "service": "https",
                "http_request": "GET /login",
                "http_response": "HTTP/1.1 200 OK",
                "cves": ["CVE-2026-1234"],
                "description": "Acunetix branding must be removed",
                "solution": "Use parameterized queries",
                "affected_url": "https://example.com/login",
            }
        ],
        summary={},
        total_findings=1,
        unique_urls=1,
        risk_score=90,
        status="completed",
        target_url="https://example.com",
        started_at=None,
        finished_at=None,
    )

    pdf = _build_dynamic_webscan_pdf(record, "developer")
    text = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf)).pages)

    assert "Acunetix" not in text
    assert "CWE-89" in text
    assert "9.8" in text
    assert "85%" in text
    assert "Vulnerability ID: vuln-1" in text
    assert "GET /login" in text
    assert "CVE-2026-1234" in text
    assert "iSecurify" in text


def test_semgrep_findings_include_source_lines_recommendation_and_autofix():
    findings = _semgrep_payload_to_findings({
        "results": [{
            "check_id": "python.lang.security.audit.sql-injection",
            "path": "src/data.py",
            "start": {"line": 41},
            "end": {"line": 42},
            "extra": {
                "severity": "ERROR",
                "message": "Possible SQL injection",
                "lines": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
                "fix": 'cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))',
                "metadata": {
                    "name": "SQL injection",
                    "cwe": ["CWE-89"],
                    "remediation": "Use a parameterized query.",
                },
            },
        }],
    })

    assert len(findings) == 1
    finding = findings[0]
    assert finding["name"] == "SQL injection"
    assert finding["title"] == "SQL injection"
    assert finding["plugin_id"] == "Semgrep"
    assert "rule_id" not in finding
    assert finding["file"] == "src/data.py"
    assert finding["line_range"] == "41-42"
    assert finding["description"] == "Possible SQL injection"
    assert finding["solution"] == "Use a parameterized query."
    assert "cursor.execute" in finding["evidence"]
    assert "cursor.execute" in finding["autofix"]


def test_static_report_is_branded_and_includes_semgrep_finding_details():
    record = SimpleNamespace(
        target_url="https://github.com/acme/example",
        status="completed",
        total_findings=1,
        unique_urls=1,
        risk_score=75,
        severity="high",
        severity_distribution={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        findings=[{
            "title": "python.lang.security.audit.sql-injection",
            "source": "semgrep",
            "plugin_family": "Semgrep",
            "rule_id": "python.lang.security.audit.sql-injection",
            "severity": "high",
            "severity_label": "high",
            "file": "src/data.py",
            "line_range": "41-42",
            "cwe": ["CWE-89"],
            "description": "Possible SQL injection in the query.",
            "solution": "Use a parameterized query.",
            "evidence": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
            "autofix": 'cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))',
        }],
    )

    pdf = _build_static_webscan_pdf(record)
    reader = PdfReader(BytesIO(pdf))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert any(page.images for page in reader.pages)
    assert "iSecurify" in text
    assert "Static Repository Security Report" in text
    assert "Semgrep" in text
    assert "python.lang.security.audit.sql-injection" not in text
    assert "src/data.py" in text
    assert "41-42" in text
    assert "Possible SQL injection in the query." in text
    assert "Use a parameterized query." in text
    assert "matched source lines" in text
    assert "Semgrep autofix suggestion" in text


@pytest.mark.parametrize(
    "configured, expected",
    [
        # Bare console address — the /api/v1 root is appended.
        ("https://acunetix.example.com:3443", "https://acunetix.example.com:3443/api/v1"),
        ("https://acunetix.example.com:3443/", "https://acunetix.example.com:3443/api/v1"),
        # Already an API root: left alone.
        ("https://acunetix.example.com:3443/api/v1", "https://acunetix.example.com:3443/api/v1"),
        ("https://acunetix.example.com:3443/api/v1/", "https://acunetix.example.com:3443/api/v1"),
        # "/api" without the version gets the version added.
        ("https://acunetix.example.com:3443/api", "https://acunetix.example.com:3443/api/v1"),
        # Browser-console URL pasted straight from the address bar.
        (
            "https://acunetix.example.com:3443/#/dashboard",
            "https://acunetix.example.com:3443/api/v1",
        ),
        ("https://acunetix.example.com:3443/?x=1", "https://acunetix.example.com:3443/api/v1"),
        # Sub-path installation is preserved.
        (
            "https://host.example.com/acunetix/api/v1",
            "https://host.example.com/acunetix/api/v1",
        ),
        ("https://host.example.com/acunetix", "https://host.example.com/acunetix/api/v1"),
        # Scheme is assumed when omitted, and stray whitespace is trimmed.
        ("  acunetix.example.com:3443  ", "https://acunetix.example.com:3443/api/v1"),
        # Scheme-relative values must not become "https://https://…".
        ("https://acunetix.internal", "https://acunetix.internal/api/v1"),
    ],
)
def test_resolve_base_url_normalizes_configured_value(monkeypatch, configured, expected):
    monkeypatch.setenv("ACUNETIX_URL", configured)
    assert resolve_base_url() == expected


def test_resolve_base_url_prefers_url_over_base_url_alias(monkeypatch):
    monkeypatch.setenv("ACUNETIX_URL", "https://primary:3443")
    monkeypatch.setenv("ACUNETIX_BASE_URL", "https://legacy:3443")

    assert resolve_base_url() == "https://primary:3443/api/v1"


def test_resolve_base_url_falls_back_to_legacy_alias(monkeypatch):
    monkeypatch.setenv("ACUNETIX_BASE_URL", "https://legacy:3443")

    assert resolve_base_url() == "https://legacy:3443/api/v1"


@pytest.mark.parametrize("configured", ["", "   ", "#/dashboard"])
def test_resolve_base_url_returns_empty_when_unconfigured(monkeypatch, configured):
    monkeypatch.setenv("ACUNETIX_URL", configured)
    assert resolve_base_url() == ""


def test_resolve_base_url_returns_empty_when_nothing_is_set():
    assert resolve_base_url() == ""


def test_resolve_base_url_accepts_explicit_override():
    assert resolve_base_url("acunetix.example.com:3443/") == "https://acunetix.example.com:3443/api/v1"


def test_error_detail_keeps_acunetix_validation_field_details():
    class ValidationResponse:
        @staticmethod
        def json():
            return {
                "message": "Validation errors",
                "errors": [{"field": "address", "message": "Invalid target"}],
            }

    detail = _error_detail(ValidationResponse())

    assert "Validation errors" in detail
    assert '"field": "address"' in detail
    assert "Invalid target" in detail


# ─── Settings read from the environment ───────────────────────────────────────


def test_env_float_reads_the_configured_value(monkeypatch):
    monkeypatch.setenv("ACUNETIX_HTTP_TIMEOUT_SEC", "45")
    assert _env_float("ACUNETIX_HTTP_TIMEOUT_SEC", 30.0) == 45.0


def test_env_float_falls_back_when_unset_or_invalid(monkeypatch):
    monkeypatch.delenv("ACUNETIX_HTTP_TIMEOUT_SEC", raising=False)
    assert _env_float("ACUNETIX_HTTP_TIMEOUT_SEC", 30.0) == 30.0

    monkeypatch.setenv("ACUNETIX_HTTP_TIMEOUT_SEC", "not-a-number")
    assert _env_float("ACUNETIX_HTTP_TIMEOUT_SEC", 30.0) == 30.0

    monkeypatch.setenv("ACUNETIX_HTTP_TIMEOUT_SEC", "   ")
    assert _env_float("ACUNETIX_HTTP_TIMEOUT_SEC", 30.0) == 30.0


@pytest.mark.parametrize(
    "configured, expected",
    [("true", True), ("1", True), ("on", True), ("yes", True),
     ("false", False), ("0", False), ("off", False)],
)
def test_env_bool_parses_truthy_and_falsy(monkeypatch, configured, expected):
    monkeypatch.setenv("ACUNETIX_VERIFY_TLS", configured)
    assert _env_bool("ACUNETIX_VERIFY_TLS", False) is expected


def test_env_bool_falls_back_when_unset(monkeypatch):
    monkeypatch.delenv("ACUNETIX_VERIFY_TLS", raising=False)
    assert _env_bool("ACUNETIX_VERIFY_TLS", False) is False
    assert _env_bool("ACUNETIX_VERIFY_TLS", True) is True


def test_client_timeout_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("ACUNETIX_URL", "https://acunetix.example.com:3443")
    monkeypatch.setenv("ACUNETIX_API_KEY", "test-key")
    monkeypatch.setenv("ACUNETIX_HTTP_TIMEOUT_SEC", "7")

    client = AcunetixClient()
    try:
        assert client._client.timeout.read == 7.0
    finally:
        client.close()


# ─── Scanning profile selection ───────────────────────────────────────────────

FULL_SCAN = {"profile_id": "p-full", "name": "Full Scan"}
CRAWL_ONLY = {"profile_id": "p-crawl", "name": "Crawl Only"}
SQLI = {"profile_id": "p-sqli", "name": "SQL Injection"}


def _client_with_profiles(monkeypatch, profiles, configured=""):
    """A client whose profile listing is stubbed — no network access."""
    monkeypatch.setenv("ACUNETIX_URL", "https://acunetix.example.com:3443")
    monkeypatch.setenv("ACUNETIX_API_KEY", "test-key")
    if configured:
        monkeypatch.setenv("ACUNETIX_PROFILE_ID", configured)
    else:
        monkeypatch.delenv("ACUNETIX_PROFILE_ID", raising=False)

    client = AcunetixClient()
    client.list_profiles = lambda: profiles
    return client


def test_profile_id_env_var_wins(monkeypatch):
    client = _client_with_profiles(monkeypatch, [CRAWL_ONLY, FULL_SCAN], configured="p-custom")
    assert client.resolve_profile_id() == "p-custom"


def test_profile_selection_prefers_full_scan(monkeypatch):
    client = _client_with_profiles(monkeypatch, [CRAWL_ONLY, FULL_SCAN, SQLI])
    assert client.resolve_profile_id() == "p-full"


def test_profile_selection_leaves_aspect_black_when_nothing_matches(monkeypatch):
    """Never blind-pick the first profile: a crawl-only one reports no findings."""
    client = _client_with_profiles(monkeypatch, [CRAWL_ONLY, SQLI])
    assert client.resolve_profile_id() == ""


def test_profile_selection_raises_when_account_has_no_profiles(monkeypatch):
    client = _client_with_profiles(monkeypatch, [])
    with pytest.raises(AcunetixError):
        client.resolve_profile_id()


def test_start_scan_omits_profile_id_when_unresolved(monkeypatch):
    """Omitting profile_id lets Acunetix apply its own default."""
    client = _client_with_profiles(monkeypatch, [CRAWL_ONLY])
    captured = {}

    def fake_request(method, path, **kwargs):
        captured["method"] = method
        captured["path"] = path
        captured["body"] = kwargs.get("json")
        return {"scan_id": "scan-1"}

    client._request = fake_request
    assert client.start_scan("target-1") == "scan-1"
    assert captured["path"] == "/scans"
    assert "profile_id" not in captured["body"]
    assert captured["body"]["target_id"] == "target-1"


def test_start_scan_sends_profile_id_when_resolved(monkeypatch):
    client = _client_with_profiles(monkeypatch, [FULL_SCAN])
    captured = {}

    def fake_request(method, path, **kwargs):
        captured["body"] = kwargs.get("json")
        return {"scan_id": "scan-1"}

    client._request = fake_request
    client.start_scan("target-1")
    assert captured["body"]["profile_id"] == "p-full"


# ─── Target lookup (find_target_by_address) ─────────────────────────────────


def _client_with_target_pages(monkeypatch, pages):
    """A client whose GET /targets responses are stubbed, capturing params."""
    monkeypatch.setenv("ACUNETIX_URL", "https://acunetix.example.com:3443")
    monkeypatch.setenv("ACUNETIX_API_KEY", "test-key")

    client = AcunetixClient()
    state = {"calls": 0, "params": []}

    def fake_request(method, path, **kwargs):
        assert (method, path) == ("GET", "/targets")
        params = kwargs.get("params") or {}
        state["params"].append(params)
        page = pages[min(state["calls"], len(pages) - 1)]
        state["calls"] += 1
        return page

    client._request = fake_request
    client._captured = state
    return client


def test_find_target_matches_address_without_a_q_filter(monkeypatch):
    """A raw URL must never be sent as ``q`` — Acunetix 400s on it (it is a
    structured filter expression, not free-text search)."""
    client = _client_with_target_pages(monkeypatch, [{
        "targets": [{"target_id": "t-1", "address": "https://www.isecurify.co"}],
        "pagination": {},
    }])

    assert client.find_target_by_address("https://www.isecurify.co") == "t-1"
    sent = client._captured["params"][0]
    assert "q" not in sent, "raw URL in q= makes Acunetix return 400 Validation errors"
    assert "page_size" not in sent


def test_find_target_normalizes_trailing_slash_and_case(monkeypatch):
    client = _client_with_target_pages(monkeypatch, [{
        "targets": [{"target_id": "t-1", "address": "https://WWW.ISecurify.co/"}],
        "pagination": {},
    }])

    assert client.find_target_by_address("https://www.isecurify.co") == "t-1"


def test_find_target_returns_none_when_address_is_absent(monkeypatch):
    client = _client_with_target_pages(monkeypatch, [{
        "targets": [{"target_id": "t-other", "address": "https://other.example.com"}],
        "pagination": {},
    }])

    assert client.find_target_by_address("https://www.isecurify.co") is None


def test_find_target_walks_cursor_pagination(monkeypatch):
    pages = [
        {
            "targets": [{"target_id": "t-0", "address": "https://a.example.com"}],
            "pagination": {"cursor": "page-2"},
        },
        {
            "targets": [{"target_id": "t-1", "address": "https://www.isecurify.co"}],
            "pagination": {},
        },
    ]
    client = _client_with_target_pages(monkeypatch, pages)

    assert client.find_target_by_address("https://www.isecurify.co") == "t-1"
    first, second = client._captured["params"]
    assert first["l"] == 100 and "c" not in first
    assert second["c"] == "page-2"


def test_find_target_handles_empty_address(monkeypatch):
    client = _client_with_target_pages(monkeypatch, [{"targets": [], "pagination": {}}])
    assert client.find_target_by_address("   ") is None
    assert client._captured["params"] == []


# ─── Authentication configuration (configure_authentication) ─────────────────


@pytest.mark.parametrize(
    ("criticality", "expected"),
    [
        ("critical", 30),
        ("high", 20),
        ("medium", 10),
        ("normal", 10),
        ("low", 0),
        (None, 10),
    ],
)
def test_map_criticality_matches_acunetix_scale(criticality, expected):
    assert map_criticality(criticality) == expected


def test_map_criticality_rejects_unknown_values():
    with pytest.raises(ValueError, match="Unsupported target criticality"):
        map_criticality("urgent")


def _capturing_client(monkeypatch):
    """A client whose _request is stubbed, recording the last call."""
    monkeypatch.setenv("ACUNETIX_URL", "https://acunetix.example.com:3443")
    monkeypatch.setenv("ACUNETIX_API_KEY", "test-key")

    client = AcunetixClient()
    state: dict = {}

    def fake_request(method, path, **kwargs):
        state["method"] = method
        state["path"] = path
        state["body"] = kwargs.get("json")
        return {}

    client._request = fake_request
    client._captured = state
    return client


def test_create_target_sends_acunetix_criticality_value(monkeypatch):
    client = _capturing_client(monkeypatch)
    calls = []

    def fake_request(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        if method == "GET":
            return {"targets": [], "pagination": {}}
        return {"target_id": "t-1"}

    client._request = fake_request

    assert client.create_target("https://example.com", criticality=30) == "t-1"
    assert calls[-1] == (
        "POST",
        "/targets",
        {
            "address": "https://example.com",
            "description": "ShieldStat web scan for https://example.com",
            "criticality": 30,
        },
    )


def test_reused_target_updates_acunetix_criticality_value(monkeypatch):
    client = _capturing_client(monkeypatch)
    calls = []

    def fake_request(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        if method == "GET":
            return {
                "targets": [{"target_id": "t-1", "address": "https://example.com"}],
                "pagination": {},
            }
        return {}

    client._request = fake_request

    assert client.create_target("https://example.com", criticality=0) == "t-1"
    assert calls[-1] == (
        "PUT",
        "/targets/t-1",
        {
            "address": "https://example.com",
            "description": "",
            "criticality": 0,
        },
    )


@pytest.mark.parametrize(
    ("method", "kwargs", "message"),
    [
        ("basic", {"username": "alice"}, "username and password"),
        ("basic", {"password": "secret"}, "username and password"),
        ("api_token", {}, "token value"),
    ],
)
def test_configure_authentication_rejects_missing_credentials(
    monkeypatch, method, kwargs, message
):
    client = _capturing_client(monkeypatch)

    with pytest.raises(AcunetixError, match=message):
        client.configure_authentication("t-1", method=method, **kwargs)

    assert client._captured == {}


def test_configure_authentication_basic_sends_credentials(monkeypatch):
    client = _capturing_client(monkeypatch)

    note = client.configure_authentication(
        "t-1", method="basic", username="alice", password="s3cret"
    )

    assert note is None
    assert client._captured["method"] == "PATCH"
    assert client._captured["path"] == "/targets/t-1/configuration"
    assert client._captured["body"] == {
        "authentication": {
            "enabled": True,
            "username": "alice",
            "password": "s3cret",
        },
        "login": {"kind": "none"},
        "custom_headers": [],
        "custom_cookies": [],
    }


def test_configure_authentication_preserves_password_whitespace(monkeypatch):
    client = _capturing_client(monkeypatch)

    client.configure_authentication(
        "t-1", method="basic", username="alice", password="  passphrase  "
    )

    assert client._captured["body"]["authentication"]["password"] == "  passphrase  "


def test_configure_authentication_api_token_sends_custom_header(monkeypatch):
    client = _capturing_client(monkeypatch)

    note = client.configure_authentication(
        "t-1",
        method="api_token",
        token_header="X-Api-Key",
        token_value="abc123",
    )

    assert note is None
    assert client._captured["method"] == "PATCH"
    assert client._captured["body"] == {
        "authentication": {"enabled": False},
        "login": {"kind": "none"},
        "custom_headers": ["X-Api-Key: abc123"],
        "custom_cookies": [],
    }


def test_configure_authentication_defaults_header_name_to_authorization(monkeypatch):
    client = _capturing_client(monkeypatch)

    client.configure_authentication(
        "t-1", method="api_token", token_header="   ", token_value="Bearer xyz"
    )

    assert client._captured["body"]["custom_headers"][0].startswith("Authorization: ")


@pytest.mark.parametrize("method", ["username_password", "sso", "mfa", "other", ""])
def test_configure_authentication_rejects_unverified_methods(monkeypatch, method):
    """Methods without a confirmed API shape must not hit the config endpoint."""
    client = _capturing_client(monkeypatch)

    with pytest.raises(AcunetixError, match="Unsupported Acunetix authentication method"):
        client.configure_authentication("t-1", method=method, username="a", password="b")

    assert client._captured == {}, "no request may be sent for unverified methods"
