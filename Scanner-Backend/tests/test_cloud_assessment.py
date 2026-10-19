import json
import os
from io import BytesIO
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi import HTTPException
from pydantic import TypeAdapter, ValidationError
from pypdf import PdfReader

from app.api.cloud_assessment.report import generate_cloud_assessment_pdf
from app.api.cloud_assessment.schemas import CloudAssessmentRequest
from app.api.cloud_assessment.routes import router as cloud_assessment_router
from app.api.cloud_assessment import service as cloud_assessment_service
from app.api.cloud_assessment import routes as cloud_assessment_routes
from app.core.middleware import require_cloud_assessment_access
from app.api.cloud_assessment.service import (
    _normalize_csv_findings,
    _provider_environment,
    _scan_command,
    _summarize_findings,
    request_credentials,
)


def test_cloud_assessment_pdf_uses_executive_report_layout():
    report = generate_cloud_assessment_pdf(
        {
            "scan_id": "scan-report-test",
            "provider": "aws",
            "scope": {"regions": ["us-east-1"]},
            "status": "completed",
            "created_at": "2026-10-15T10:00:00+00:00",
            "completed_at": "2026-10-15T10:05:00+00:00",
            "summary": {
                "account_id": "123456789012",
                "total_checks": 3,
                "failed_checks": 1,
                "passed_checks": 1,
                "manual_checks": 1,
                "muted_checks": 0,
                "skipped_checks": 0,
                "severity_counts": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "informational": 0,
                },
            },
            "findings": [
                {
                    "check_id": "check-storage-public",
                    "title": "Storage must not be public",
                    "status": "FAIL",
                    "severity": "high",
                    "service": "s3",
                    "region": "us-east-1",
                    "resource_id": "bucket-1",
                    "compliance": ["CIS: 2.1"],
                    "status_extended": "Bucket permits public reads.",
                    "risk": "Public reads can expose stored data.\u200b",
                    "remediation": "Block public access.",
                },
                {
                    "check_id": "check-encryption",
                    "title": "Encryption enabled",
                    "status": "PASS",
                    "severity": "high",
                    "service": "s3",
                    "region": "us-east-1",
                    "resource_id": "bucket-2",
                    "compliance": ["CIS: 2.2"],
                },
                {
                    "check_id": "check-manual",
                    "title": "Review key rotation",
                    "status": "MANUAL",
                    "severity": "medium",
                    "service": "iam",
                    "region": "global",
                },
            ],
        }
    )

    pdf = PdfReader(BytesIO(report))
    text = "\n".join(page.extract_text() or "" for page in pdf.pages)

    assert report.startswith(b"%PDF-")
    assert "Executive Security Report" in text
    assert "Security Posture Score" in text
    assert "GRADE C" in text
    assert "Findings by Severity" in text
    assert "Regulatory & Compliance Framework Alignment" not in text
    assert "Finding Status Guide" in text
    assert "Security Findings Explorer" in text
    assert "Manual Verification Required" in text
    assert "Passed Security Controls" in text
    assert "AFFECTED RESOURCE / SCOPE" in text
    assert "STATUS DETAILS" in text
    assert "RISK IMPACT" in text
    assert "REMEDIATION GUIDANCE" in text
    assert "compliance" not in text.lower()
    assert "CIS" not in text
    assert "\u200b" not in text
    assert "\u25a0" not in text


def test_cloud_assessment_access_requires_admin_approval():
    unapproved_user = SimpleNamespace(cloud_assessment_approved=False)

    with pytest.raises(HTTPException) as error:
        require_cloud_assessment_access(unapproved_user)

    assert error.value.status_code == 403
    assert "not been approved" in error.value.detail


def test_approved_user_can_pass_cloud_assessment_access_check():
    approved_user = SimpleNamespace(cloud_assessment_approved=True)

    assert require_cloud_assessment_access(approved_user) is approved_user


def test_cloud_assessment_scan_routes_require_approved_access():
    expected_paths = {
        ("POST", "/cloud-assessment/scans"),
        ("GET", "/cloud-assessment/scans"),
        ("GET", "/cloud-assessment/scans/{scan_id}"),
        ("GET", "/cloud-assessment/scans/{scan_id}/report"),
    }
    guarded_routes = {
        (method, route.path): route
        for route in cloud_assessment_router.routes
        for method in route.methods or set()
        if (method, route.path) in expected_paths
    }

    assert set(guarded_routes) == expected_paths
    for route in guarded_routes.values():
        assert any(
            dependency.call is require_cloud_assessment_access
            for dependency in route.dependant.dependencies
        )


def test_scan_serialization_hides_legacy_version_and_caller_metadata():
    scan = SimpleNamespace(
        scan_id="scan-1",
        provider="aws",
        scope={},
        status="completed",
        summary={
            "total_checks": 1,
            "metadata": {
                "prowler_version": "5.45.0",
                "caller_identity": {"Account": "123456789012"},
            },
        },
        error=None,
        created_at=None,
        completed_at=None,
        findings=[{"check_id": "check-1", "prowler_version": "5.45.0"}],
    )

    serialized = cloud_assessment_routes._serialize_scan(scan, include_findings=True)

    assert "metadata" not in serialized["summary"]
    assert serialized["summary"]["account_id"] == "123456789012"
    assert "prowler_version" not in serialized["findings"][0]
    assert "metadata" in scan.summary


def test_cloud_assessment_request_validates_aws_credentials():
    request = TypeAdapter(CloudAssessmentRequest).validate_python(
        {
            "provider": "aws",
            "access_key_id": "AKIAABCDEFGHIJKLMNOP",
            "secret_access_key": "aws-secret",
            "session_token": "temporary-session-token",
        }
    )

    provider, scope, credentials = request_credentials(request)

    assert provider == "aws"
    assert scope == {}
    assert credentials == {
        "access_key_id": "AKIAABCDEFGHIJKLMNOP",
        "secret_access_key": "aws-secret",
        "session_token": "temporary-session-token",
    }


def test_cloud_assessment_request_accepts_and_normalizes_aws_region():
    request = TypeAdapter(CloudAssessmentRequest).validate_python(
        {
            "provider": "aws",
            "access_key_id": "AKIAABCDEFGHIJKLMNOP",
            "secret_access_key": "aws-secret",
            "aws_region": " US-EAST-1 ",
        }
    )

    provider, scope, _ = request_credentials(request)

    assert provider == "aws"
    assert scope == {"region": "us-east-1"}


def test_cloud_assessment_request_accepts_multiple_aws_regions():
    request = TypeAdapter(CloudAssessmentRequest).validate_python(
        {
            "provider": "aws",
            "access_key_id": "AKIAABCDEFGHIJKLMNOP",
            "secret_access_key": "aws-secret",
            "aws_regions": [" US-WEST-2 ", "us-east-1"],
        }
    )

    provider, scope, _ = request_credentials(request)

    assert provider == "aws"
    assert scope == {"regions": ["us-east-1", "us-west-2"]}


def test_cloud_assessment_request_rejects_malformed_aws_region():
    with pytest.raises(ValidationError):
        TypeAdapter(CloudAssessmentRequest).validate_python(
            {
                "provider": "aws",
                "access_key_id": "AKIAABCDEFGHIJKLMNOP",
                "secret_access_key": "aws-secret",
                "aws_region": "us-east",
            }
        )


@pytest.mark.parametrize(
    "regions",
    [
        [],
        ["us-east-1", "us-east-1"],
        ["us-east"],
    ],
)
def test_cloud_assessment_request_rejects_invalid_aws_region_selection(regions):
    with pytest.raises(ValidationError):
        TypeAdapter(CloudAssessmentRequest).validate_python(
            {
                "provider": "aws",
                "access_key_id": "AKIAABCDEFGHIJKLMNOP",
                "secret_access_key": "aws-secret",
                "aws_regions": regions,
            }
        )


def test_cloud_assessment_request_requires_explicit_azure_and_gcp_scope():
    with pytest.raises(ValidationError):
        TypeAdapter(CloudAssessmentRequest).validate_python(
            {
                "provider": "azure",
                "tenant_id": "tenant",
                "client_id": "client",
                "client_secret": "secret",
            }
        )

    with pytest.raises(ValidationError):
        TypeAdapter(CloudAssessmentRequest).validate_python(
            {
                "provider": "gcp",
                "service_account_json": json.dumps({"type": "service_account"}),
                "project_ids": [],
            }
        )


def test_gcp_credentials_are_not_in_assessment_scope():
    request = TypeAdapter(CloudAssessmentRequest).validate_python(
        {
            "provider": "gcp",
            "service_account_json": json.dumps(
                {"type": "service_account", "private_key": "gcp-secret"}
            ),
            "project_ids": ["project-one"],
        }
    )

    provider, scope, credentials = request_credentials(request)

    assert provider == "gcp"
    assert scope == {"project_ids": ["project-one"]}
    assert "gcp-secret" in credentials["service_account_json"]
    assert "gcp-secret" not in json.dumps(scope)


def test_prowler_command_uses_selected_cloud_scope_and_csv_output(tmp_path):
    executable = str(tmp_path / "prowler")
    command = _scan_command(
        "azure",
        tmp_path,
        {"subscription_ids": ["subscription-one", "subscription-two"]},
        executable=executable,
    )

    assert command[:2] == [executable, "azure"]
    assert command[command.index("--subscription-ids") + 1 :] == [
        "subscription-one",
        "subscription-two",
    ]
    assert command[command.index("--output-formats") + 1] == "csv"
    assert str(tmp_path) in command


@pytest.mark.parametrize(
    ("scope", "expected_region_args"),
    [
        ({}, []),
        ({"region": "us-east-1"}, ["--region", "us-east-1"]),
        (
            {"regions": ["us-east-1", "us-west-2"]},
            ["--region", "us-east-1", "us-west-2"],
        ),
    ],
)
def test_aws_prowler_command_respects_selected_region_scope(
    tmp_path, scope, expected_region_args
):
    command = _scan_command(
        "aws",
        tmp_path,
        scope,
        executable="prowler",
    )

    assert command[command.index("--output-formats") + 1] == "csv"
    if expected_region_args:
        region_index = command.index("--region")
        assert command[region_index : region_index + len(expected_region_args)] == expected_region_args
    else:
        assert "--region" not in command


def test_assessment_environment_does_not_reuse_host_cloud_credentials():
    process_environment = _provider_environment(
        {
            "AWS_ACCESS_KEY_ID": "host-access-key",
            "AWS_SECRET_ACCESS_KEY": "host-secret",
            "AZURE_CLIENT_SECRET": "host-azure-secret",
            "GOOGLE_APPLICATION_CREDENTIALS": "host-service-account.json",
            "PATH": "scanner-path",
        },
        "aws",
        {"access_key_id": "scan-access-key", "secret_access_key": "scan-secret", "session_token": ""},
    )

    assert process_environment["AWS_ACCESS_KEY_ID"] == "scan-access-key"
    assert process_environment["AWS_SECRET_ACCESS_KEY"] == "scan-secret"
    assert "AZURE_CLIENT_SECRET" not in process_environment
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in process_environment
    assert process_environment["PATH"] == "scanner-path"


@pytest.mark.parametrize(
    ("provider", "credentials", "expected_secret"),
    [
        (
            "aws",
            {"access_key_id": "scan-access", "secret_access_key": "scan-secret", "session_token": ""},
            "scan-secret",
        ),
        (
            "azure",
            {"tenant_id": "tenant", "client_id": "client", "client_secret": "azure-secret"},
            "azure-secret",
        ),
        (
            "gcp",
            {
                "service_account_json": (
                    '{"private_key":"gcp-secret","client_email":"scanner@example.iam.gserviceaccount.com",'
                    '"project_id":"security-project"}'
                )
            },
            "gcp-secret",
        ),
    ],
)
def test_credential_preflight_uses_provider_credentials_without_cli_secrets(
    monkeypatch, provider, credentials, expected_secret
):
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout="123456789012",
        )

    monkeypatch.setattr(cloud_assessment_service, "PROWLER_EXECUTABLE", "prowler")
    monkeypatch.setattr(cloud_assessment_service, "PROWLER_PYTHON_EXECUTABLE", "prowler-python")
    monkeypatch.setattr(cloud_assessment_service.shutil, "which", lambda _executable: "prowler")
    monkeypatch.setattr(cloud_assessment_service.subprocess, "run", run)

    account_id = cloud_assessment_service.validate_cloud_credentials(provider, credentials)

    assert expected_secret not in " ".join(captured["command"])
    assert captured["stdout"] == (
        cloud_assessment_service.subprocess.PIPE
        if provider == "aws"
        else cloud_assessment_service.subprocess.DEVNULL
    )
    assert captured["stderr"] == cloud_assessment_service.subprocess.DEVNULL
    if provider == "gcp":
        assert captured["input"] == credentials["service_account_json"]
        assert "GOOGLE_APPLICATION_CREDENTIALS" not in captured["env"]
    else:
        assert captured["input"] is None
        credential_variable = (
            "AWS_SECRET_ACCESS_KEY" if provider == "aws" else "AZURE_CLIENT_SECRET"
        )
        assert captured["env"][credential_variable] == expected_secret
    assert account_id == ("123456789012" if provider == "aws" else None)
def test_failed_credential_preflight_does_not_consume_scan_quota(monkeypatch):
    request = TypeAdapter(CloudAssessmentRequest).validate_python(
        {
            "provider": "aws",
            "access_key_id": "AKIAABCDEFGHIJKLMNOP",
            "secret_access_key": "invalid-secret",
        }
    )
    quota_reservations = []

    def reject_credentials(_provider, _credentials):
        raise cloud_assessment_service.CloudCredentialValidationError(
            "Could not authenticate the AWS credentials."
        )

    monkeypatch.setattr(cloud_assessment_routes, "validate_cloud_credentials", reject_credentials)
    monkeypatch.setattr(
        cloud_assessment_routes,
        "reserve_scan_quota",
        lambda *_args: quota_reservations.append("reserved"),
    )

    with pytest.raises(HTTPException) as error:
        cloud_assessment_routes.create_cloud_assessment(
            request,
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(user_id="user-1"),
        )

    assert error.value.status_code == 400
    assert quota_reservations == []


def test_assessment_reserves_quota_only_after_credentials_are_verified(monkeypatch):
    request = TypeAdapter(CloudAssessmentRequest).validate_python(
        {
            "provider": "aws",
            "access_key_id": "AKIAABCDEFGHIJKLMNOP",
            "secret_access_key": "valid-secret",
        }
    )
    events = []

    class FakeDb:
        def add(self, _scan):
            events.append("persist")

        def commit(self):
            pass

        def refresh(self, _scan):
            pass

    def verify_credentials(*_args):
        events.append("verify")
        return "123456789012"

    scheduled = {}

    def schedule_task(function, *args):
        events.append("schedule")
        scheduled["function"] = function
        scheduled["args"] = args

    monkeypatch.setattr(cloud_assessment_routes, "validate_cloud_credentials", verify_credentials)
    monkeypatch.setattr(
        cloud_assessment_routes,
        "reserve_scan_quota",
        lambda *_args: events.append("reserve"),
    )

    result = cloud_assessment_routes.create_cloud_assessment(
        request,
        SimpleNamespace(add_task=schedule_task),
        FakeDb(),
        SimpleNamespace(user_id="user-1"),
    )

    assert events == ["verify", "reserve", "persist", "schedule"]
    assert result["status"] == "running"
    assert result["summary"]["account_id"] == "123456789012"
    assert len(scheduled["args"]) == 5


def test_prowler_findings_are_normalized_and_summarized():
    findings = _normalize_csv_findings(
        "CHECK_ID;CHECK_TITLE;COMPLIANCE;PROWLER_VERSION;RESOURCE_TAGS;STATUS;"
        "STATUS_EXTENDED;SEVERITY;SERVICE_NAME;RESOURCE_UID;RISK;REMEDIATION_RECOMMENDATION_TEXT\n"
        "iam_example;Enable MFA;CIS: 1.1 | NIST: AC-2;5.45.0;owner=security | env=prod;"
        "FAIL;MFA disabled;high;iam;user/123;Unauthorized access could expose sensitive data;Enable MFA\n"
        "s3_example;Block public access;;;;PASS;Bucket is private;low;s3;bucket-1;\n"
    )

    assert findings[0]["check_id"] == "iam_example"
    assert findings[0]["resource_id"] == "user/123"
    assert findings[0]["compliance"] == ["CIS: 1.1", "NIST: AC-2"]
    assert findings[0]["resource_tags"] == {"owner": "security", "env": "prod"}
    assert "prowler_version" not in findings[0]
    assert findings[0]["risk"] == "Unauthorized access could expose sensitive data"
    assert findings[1]["status"] == "PASS"
    assert _summarize_findings(findings) == {
        "total_checks": 2,
        "failed_checks": 1,
        "passed_checks": 1,
        "manual_checks": 0,
        "muted_checks": 0,
        "not_applicable_checks": 0,
        "errored_checks": 0,
        "skipped_checks": 0,
        "checks_unavailable": 0,
        "other_checks": 0,
        "severity_counts": {
            "critical": 0,
            "high": 1,
            "informational": 0,
            "low": 0,
            "medium": 0,
        },
    }


def test_cloud_assessment_summary_counts_errored_and_skipped_checks():
    summary = _summarize_findings(
        [
            {"status": "ERROR", "severity": "high"},
            {"status": "SKIP", "severity": "low"},
            {"status": "SKIPPED", "severity": "low"},
            {"status": "PASS", "severity": "low"},
        ]
    )

    assert summary["errored_checks"] == 1
    assert summary["skipped_checks"] == 2
    assert summary["checks_unavailable"] == 3
    assert (
        summary["passed_checks"]
        + summary["failed_checks"]
        + summary["manual_checks"]
        + summary["muted_checks"]
        + summary["not_applicable_checks"]
        + summary["errored_checks"]
        + summary["skipped_checks"]
        + summary["other_checks"]
        == summary["total_checks"]
    )


def test_cloud_assessment_summary_accounts_for_manual_muted_not_applicable_and_unknown():
    summary = _summarize_findings(
        [
            {"status": "PASS"},
            {"status": "FAIL"},
            {"status": "MANUAL"},
            {"status": "MUTED"},
            {"status": "NOT_APPLICABLE"},
            {"status": "UNKNOWN_STATUS"},
        ]
    )

    assert summary["total_checks"] == 6
    assert summary["passed_checks"] == 1
    assert summary["failed_checks"] == 1
    assert summary["manual_checks"] == 1
    assert summary["muted_checks"] == 1
    assert summary["not_applicable_checks"] == 1
    assert summary["other_checks"] == 1


def test_nonzero_prowler_exit_with_csv_report_completes_assessment(monkeypatch):
    scan = SimpleNamespace(
        status="running",
        findings=None,
        summary={"account_id": "123456789012"},
        completed_at=None,
    )

    class FakeQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return scan

    class FakeSession:
        def query(self, *_args, **_kwargs):
            return FakeQuery()

        def commit(self):
            pass

        def close(self):
            pass

    def run_prowler(command, **_kwargs):
        output_directory = command[command.index("--output-directory") + 1]
        (cloud_assessment_service.Path(output_directory) / "assessment.csv").write_text(
            "CHECK_ID;CHECK_TITLE;STATUS;STATUS_EXTENDED;SEVERITY\n"
            "iam_example;Enable MFA;FAIL;MFA disabled;high\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=3, poll=lambda: 3, wait=lambda **_wait_kwargs: 3)

    monkeypatch.setattr(cloud_assessment_service, "SessionLocal", FakeSession)
    monkeypatch.setattr(cloud_assessment_service.shutil, "which", lambda _executable: "prowler")
    monkeypatch.setattr(cloud_assessment_service.subprocess, "Popen", run_prowler)
    cloud_assessment_service.run_cloud_assessment(
        "scan-nonzero-with-report",
        "user-1",
        "aws",
        {},
        {"access_key_id": "access", "secret_access_key": "secret"},
    )

    assert scan.status == "completed"
    assert scan.summary["failed_checks"] == 1
    assert scan.summary["progress"]["stage"] == "collecting_results"
    assert scan.summary["progress"]["events"]
    assert scan.summary["account_id"] == "123456789012"
    assert "metadata" not in scan.summary
    assert scan.findings[0]["check_id"] == "iam_example"
    assert scan.completed_at is not None


def test_nonzero_prowler_exit_without_report_fails_assessment(monkeypatch):
    scan = SimpleNamespace(
        status="running",
        error=None,
        summary=None,
        completed_at=None,
    )

    class FakeQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return scan

    class FakeSession:
        def query(self, *_args, **_kwargs):
            return FakeQuery()

        def commit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(cloud_assessment_service, "SessionLocal", FakeSession)
    monkeypatch.setattr(cloud_assessment_service.shutil, "which", lambda _executable: "prowler")
    monkeypatch.setattr(
        cloud_assessment_service.subprocess,
        "Popen",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=3, poll=lambda: 3, wait=lambda **_wait_kwargs: 3),
    )

    cloud_assessment_service.run_cloud_assessment(
        "scan-nonzero-without-report",
        "user-1",
        "aws",
        {},
        {"access_key_id": "access", "secret_access_key": "secret"},
    )

    assert scan.status == "failed"
    assert "without producing a CSV report" in scan.error
    assert scan.summary["progress"]["stage"] == "failed"
    assert scan.completed_at is not None
