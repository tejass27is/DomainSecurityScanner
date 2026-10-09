import json
import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi import HTTPException
from pydantic import TypeAdapter, ValidationError

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
        ("gcp", {"service_account_json": '{"private_key":"gcp-secret"}'}, "gcp-secret"),
    ],
)
def test_credential_preflight_uses_provider_credentials_without_cli_secrets(
    monkeypatch, provider, credentials, expected_secret
):
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cloud_assessment_service, "PROWLER_EXECUTABLE", "prowler")
    monkeypatch.setattr(cloud_assessment_service, "PROWLER_PYTHON_EXECUTABLE", "prowler-python")
    monkeypatch.setattr(cloud_assessment_service.shutil, "which", lambda _executable: "prowler")
    monkeypatch.setattr(cloud_assessment_service.subprocess, "run", run)

    cloud_assessment_service.validate_cloud_credentials(provider, credentials)

    assert expected_secret not in " ".join(captured["command"])
    assert captured["stdout"] == cloud_assessment_service.subprocess.DEVNULL
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

    monkeypatch.setattr(
        cloud_assessment_routes,
        "validate_cloud_credentials",
        lambda *_args: events.append("verify"),
    )
    monkeypatch.setattr(
        cloud_assessment_routes,
        "reserve_scan_quota",
        lambda *_args: events.append("reserve"),
    )

    result = cloud_assessment_routes.create_cloud_assessment(
        request,
        SimpleNamespace(add_task=lambda *_args: events.append("schedule")),
        FakeDb(),
        SimpleNamespace(user_id="user-1"),
    )

    assert events == ["verify", "reserve", "persist", "schedule"]
    assert result["status"] == "running"


def test_prowler_findings_are_normalized_and_summarized():
    findings = _normalize_csv_findings(
        "CHECK_ID;CHECK_TITLE;STATUS;STATUS_EXTENDED;SEVERITY;SERVICE_NAME;"
        "RESOURCE_UID;REMEDIATION_RECOMMENDATION_TEXT\n"
        "iam_example;Enable MFA;FAIL;MFA disabled;high;iam;user/123;Enable MFA\n"
        "s3_example;Block public access;PASS;Bucket is private;low;s3;bucket-1;\n"
    )

    assert findings[0]["check_id"] == "iam_example"
    assert findings[0]["resource_id"] == "user/123"
    assert findings[1]["status"] == "PASS"
    assert _summarize_findings(findings) == {
        "total_checks": 2,
        "failed_checks": 1,
        "passed_checks": 1,
        "manual_checks": 0,
        "errored_checks": 0,
        "skipped_checks": 0,
        "checks_unavailable": 0,
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


def test_nonzero_prowler_exit_with_csv_report_completes_assessment(monkeypatch):
    scan = SimpleNamespace(
        status="running",
        findings=None,
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

    def run_prowler(command, **_kwargs):
        output_directory = command[command.index("--output-directory") + 1]
        (cloud_assessment_service.Path(output_directory) / "assessment.csv").write_text(
            "CHECK_ID;CHECK_TITLE;STATUS;STATUS_EXTENDED;SEVERITY\n"
            "iam_example;Enable MFA;FAIL;MFA disabled;high\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=3)

    monkeypatch.setattr(cloud_assessment_service, "SessionLocal", FakeSession)
    monkeypatch.setattr(cloud_assessment_service.shutil, "which", lambda _executable: "prowler")
    monkeypatch.setattr(cloud_assessment_service.subprocess, "run", run_prowler)

    cloud_assessment_service.run_cloud_assessment(
        "scan-nonzero-with-report",
        "user-1",
        "aws",
        {},
        {"access_key_id": "access", "secret_access_key": "secret"},
    )

    assert scan.status == "completed"
    assert scan.summary["failed_checks"] == 1
    assert scan.findings[0]["check_id"] == "iam_example"
    assert scan.completed_at is not None


def test_nonzero_prowler_exit_without_report_fails_assessment(monkeypatch):
    scan = SimpleNamespace(
        status="running",
        error=None,
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
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=3),
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
    assert scan.completed_at is not None
