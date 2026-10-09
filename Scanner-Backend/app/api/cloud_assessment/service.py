import csv
import io
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from app.api.cloud_assessment.schemas import (
    AwsAssessmentRequest,
    AzureAssessmentRequest,
    CloudAssessmentRequest,
    GcpAssessmentRequest,
)
from app.db.base import SessionLocal
from app.db.models import CloudSecurityAssessment

logger = logging.getLogger(__name__)
PROWLER_TIMEOUT_SECONDS = 60 * 60
FINDING_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
PROWLER_EXECUTABLE = os.getenv("PROWLER_EXECUTABLE", "prowler").strip() or "prowler"
PROVIDER_CREDENTIAL_ENV_VARS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_SUBSCRIPTION_ID",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_PROJECT_ID",
}


def _normalize_csv_findings(csv_text: str) -> list[dict[str, str]]:
    rows = csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff")), delimiter=";")
    findings = []
    for row in rows:
        normalized = {str(key or "").upper(): str(value or "").strip() for key, value in row.items()}
        findings.append(
            {
                "check_id": normalized.get("CHECK_ID", ""),
                "title": normalized.get("CHECK_TITLE", ""),
                "status": normalized.get("STATUS", "").upper(),
                "status_extended": normalized.get("STATUS_EXTENDED", ""),
                "severity": normalized.get("SEVERITY", "informational").lower(),
                "service": normalized.get("SERVICE_NAME", ""),
                "resource_type": normalized.get("RESOURCE_TYPE", ""),
                "resource_id": normalized.get("RESOURCE_UID", ""),
                "resource_name": normalized.get("RESOURCE_NAME", ""),
                "region": normalized.get("REGION", ""),
                "description": normalized.get("DESCRIPTION", ""),
                "remediation": normalized.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
                "remediation_url": normalized.get("REMEDIATION_RECOMMENDATION_URL", ""),
            }
        )
    return findings


def _summarize_findings(findings: list[dict[str, str]]) -> dict[str, Any]:
    failed = [finding for finding in findings if finding["status"] == "FAIL"]
    summary: dict[str, Any] = {
        "total_checks": len(findings),
        "failed_checks": len(failed),
        "passed_checks": sum(finding["status"] == "PASS" for finding in findings),
        "manual_checks": sum(finding["status"] == "MANUAL" for finding in findings),
        "severity_counts": {severity: 0 for severity in sorted(FINDING_SEVERITIES)},
    }
    for finding in failed:
        severity = finding["severity"]
        if severity in summary["severity_counts"]:
            summary["severity_counts"][severity] += 1
    return summary


def _scan_command(
    provider: str,
    output_directory: Path,
    scope: dict[str, Any],
    executable: str = "prowler",
) -> list[str]:
    command = [
        executable,
        provider,
        "--output-formats",
        "csv",
        "--output-directory",
        str(output_directory),
        "--output-filename",
        "assessment",
    ]
    if provider == "azure":
        command.extend(["--subscription-ids", *scope["subscription_ids"]])
    elif provider == "gcp":
        command.extend(["--project-ids", *scope["project_ids"]])
    return command


def _provider_environment(
    base_environment: Mapping[str, str],
    provider: str,
    credential_values: dict[str, str],
) -> dict[str, str]:
    process_environment = base_environment.copy()
    for name in PROVIDER_CREDENTIAL_ENV_VARS:
        process_environment.pop(name, None)

    if provider == "aws":
        process_environment.update(
            {
                "AWS_ACCESS_KEY_ID": credential_values["access_key_id"],
                "AWS_SECRET_ACCESS_KEY": credential_values["secret_access_key"],
            }
        )
        if credential_values.get("session_token"):
            process_environment["AWS_SESSION_TOKEN"] = credential_values["session_token"]
    elif provider == "azure":
        process_environment.update(
            {
                "AZURE_TENANT_ID": credential_values["tenant_id"],
                "AZURE_CLIENT_ID": credential_values["client_id"],
                "AZURE_CLIENT_SECRET": credential_values["client_secret"],
            }
        )
    return process_environment


def _load_csv_findings(output_directory: Path) -> list[dict[str, str]]:
    csv_files = sorted(output_directory.glob("*.csv"))
    if not csv_files:
        raise RuntimeError("Prowler completed without producing a CSV report.")
    findings = []
    for csv_file in csv_files:
        findings.extend(_normalize_csv_findings(csv_file.read_text(encoding="utf-8-sig")))
    return findings


def run_cloud_assessment(
    scan_id: str,
    user_id: str,
    provider: str,
    scope: dict[str, Any],
    credential_values: dict[str, str],
) -> None:
    """Run Prowler using short-lived credentials and persist only its results."""
    db = SessionLocal()
    try:
        if not shutil.which(PROWLER_EXECUTABLE):
            raise RuntimeError("Prowler CLI is not installed on the scanner.")

        process_env = _provider_environment(os.environ, provider, credential_values)
        temp_context = tempfile.TemporaryDirectory(prefix="cloud-assessment-")
        with temp_context as temp_directory:
            output_directory = Path(temp_directory)
            command = _scan_command(
                provider,
                output_directory,
                scope,
                executable=PROWLER_EXECUTABLE,
            )
            if provider == "gcp":
                credentials_path = output_directory / "gcp-service-account.json"
                credentials_path.write_text(credential_values["service_account_json"], encoding="utf-8")
                command.extend(["--credentials-file", str(credentials_path)])
                process_env["GOOGLE_APPLICATION_CREDENTIALS"] = str(credentials_path)

            log_path = output_directory / "prowler.log"
            with log_path.open("w", encoding="utf-8") as log_file:
                completed = subprocess.run(
                    command,
                    env=process_env,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=PROWLER_TIMEOUT_SECONDS,
                )
            if completed.returncode != 0:
                raise RuntimeError(
                    "Prowler could not complete the assessment. Verify the cloud credentials, "
                    "selected scope, and read-only access permissions."
                )
            findings = _load_csv_findings(output_directory)

        scan = db.query(CloudSecurityAssessment).filter(
            CloudSecurityAssessment.scan_id == scan_id,
            CloudSecurityAssessment.user_id == user_id,
        ).first()
        if scan is None:
            logger.error("Cloud assessment record %s disappeared before completion.", scan_id)
            return
        scan.status = "completed"
        scan.findings = findings
        scan.summary = _summarize_findings(findings)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
    except subprocess.TimeoutExpired:
        _mark_failed(
            db,
            scan_id,
            user_id,
            "Prowler exceeded the one-hour assessment time limit.",
        )
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        logger.warning("Cloud assessment %s failed: %s", scan_id, error)
        _mark_failed(db, scan_id, user_id, str(error))
    except Exception:
        logger.exception("Unexpected error while running cloud assessment %s.", scan_id)
        _mark_failed(db, scan_id, user_id, "An unexpected error prevented this assessment from completing.")
    finally:
        db.close()
        credential_values.clear()


def _mark_failed(db, scan_id: str, user_id: str, message: str) -> None:
    scan = db.query(CloudSecurityAssessment).filter(
        CloudSecurityAssessment.scan_id == scan_id,
        CloudSecurityAssessment.user_id == user_id,
    ).first()
    if scan is not None:
        scan.status = "failed"
        scan.error = message
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()


def request_credentials(request: CloudAssessmentRequest) -> tuple[str, dict[str, Any], dict[str, str]]:
    if isinstance(request, AwsAssessmentRequest):
        credentials = {
            "access_key_id": request.access_key_id,
            "secret_access_key": request.secret_access_key.get_secret_value(),
            "session_token": request.session_token.get_secret_value() if request.session_token else "",
        }
        return "aws", {}, credentials
    if isinstance(request, AzureAssessmentRequest):
        credentials = {
            "tenant_id": request.tenant_id,
            "client_id": request.client_id,
            "client_secret": request.client_secret.get_secret_value(),
        }
        return "azure", {"subscription_ids": request.subscription_ids}, credentials
    if isinstance(request, GcpAssessmentRequest):
        credentials = {
            "service_account_json": request.service_account_json.get_secret_value(),
        }
        return "gcp", {"project_ids": request.project_ids}, credentials
    raise ValueError("Unsupported cloud provider.")
