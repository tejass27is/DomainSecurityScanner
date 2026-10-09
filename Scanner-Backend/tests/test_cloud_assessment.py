import json
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from pydantic import TypeAdapter, ValidationError

from app.api.cloud_assessment.schemas import CloudAssessmentRequest
from app.api.cloud_assessment.service import (
    _normalize_csv_findings,
    _provider_environment,
    _scan_command,
    _summarize_findings,
    request_credentials,
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
        "severity_counts": {
            "critical": 0,
            "high": 1,
            "informational": 0,
            "low": 0,
            "medium": 0,
        },
    }
