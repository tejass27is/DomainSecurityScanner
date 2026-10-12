import csv
import io
import logging
import os
import shutil
import subprocess
import tempfile
import time
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
CREDENTIAL_CHECK_TIMEOUT_SECONDS = 30
PROGRESS_POLL_SECONDS = 5
PROGRESS_UPDATE_SECONDS = 15
FINDING_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
PROWLER_EXECUTABLE = os.getenv("PROWLER_EXECUTABLE", "prowler").strip() or "prowler"
PROWLER_PYTHON_EXECUTABLE = os.getenv("PROWLER_PYTHON_EXECUTABLE", "").strip()
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
CREDENTIAL_CHECKS = {
    "aws": "import boto3; print(boto3.client('sts').get_caller_identity()['Account'])",
    "azure": """
import json
import os
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

tenant_id = quote(os.environ["AZURE_TENANT_ID"], safe="")
request = Request(
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    data=urlencode({
        "client_id": os.environ["AZURE_CLIENT_ID"],
        "client_secret": os.environ["AZURE_CLIENT_SECRET"],
        "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
    }).encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
with urlopen(request, timeout=20) as response:
    if not json.load(response).get("access_token"):
        raise RuntimeError("Azure did not return an access token.")
""",
    "gcp": """
import json
import sys
from google.auth.transport.requests import Request
from google.oauth2 import service_account

credentials = service_account.Credentials.from_service_account_info(
    json.load(sys.stdin),
    scopes=["https://www.googleapis.com/auth/cloud-platform"],
)
credentials.refresh(Request())
""",
}


class CloudCredentialValidationError(RuntimeError):
    pass


def validate_cloud_credentials(
    provider: str, credential_values: dict[str, str]
) -> str | None:
    if provider not in CREDENTIAL_CHECKS:
        raise ValueError(f"Unsupported cloud provider: {provider}")
    prowler_path = shutil.which(PROWLER_EXECUTABLE)
    if not prowler_path:
        raise RuntimeError("Prowler CLI is not installed on the scanner.")

    python_executable = PROWLER_PYTHON_EXECUTABLE or str(
        Path(prowler_path).resolve().with_name("python.exe" if os.name == "nt" else "python")
    )
    process_environment = _provider_environment(os.environ, provider, credential_values)
    request_input = None
    if provider == "gcp":
        request_input = credential_values["service_account_json"]

    try:
        result = subprocess.run(
            [python_executable, "-c", CREDENTIAL_CHECKS[provider]],
            env=process_environment,
            input=request_input,
            stdout=subprocess.PIPE if provider == "aws" else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=CREDENTIAL_CHECK_TIMEOUT_SECONDS,
            text=True,
        )
    except subprocess.TimeoutExpired as error:
        logger.warning("Cloud credential preflight timed out for provider %s.", provider)
        raise CloudCredentialValidationError(
            f"Could not verify {provider.upper()} credentials before timeout. "
            "Check cloud API connectivity and try again; no scan allowance was used."
        ) from error
    except OSError as error:
        logger.exception("Could not start cloud credential preflight for provider %s.", provider)
        raise RuntimeError(
            "Cloud credential verification is unavailable on the scanner."
        ) from error

    if result.returncode != 0:
        logger.warning(
            "Cloud credential preflight failed for provider %s (exit code %s).",
            provider,
            result.returncode,
        )
        raise CloudCredentialValidationError(
            f"Could not authenticate the {provider.upper()} credentials. "
            "Check the credential values and try again; no scan allowance was used."
        )
    if provider == "aws":
        account_id = (result.stdout or "").strip()
        if not account_id.isdigit() or len(account_id) != 12:
            logger.error("AWS credential verification returned an invalid account identifier.")
            raise CloudCredentialValidationError(
                "Could not identify the AWS account for this assessment. "
                "Verify the AWS credentials and try again; no scan allowance was used."
            )
        return account_id
    return None
def _parse_delimited_mapping(value: str, pair_separator: str) -> dict[str, str]:
    mapping = {}
    for pair in value.split(" | "):
        key, separator, item_value = pair.partition(pair_separator)
        if separator and key.strip():
            mapping[key.strip()] = item_value.strip()
    return mapping


def _parse_compliance(value: str) -> list[str]:
    return [
        item.strip()
        for item in value.split(" | ")
        if item.strip()
    ]


def _normalize_csv_findings(csv_text: str) -> list[dict[str, str]]:
    rows = csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff")), delimiter=";")
    findings = []
    for row in rows:
        normalized = {str(key or "").upper(): str(value or "").strip() for key, value in row.items()}
        findings.append(
            {
                "check_id": normalized.get("CHECK_ID", ""),
                "title": normalized.get("CHECK_TITLE", ""),
                "compliance": _parse_compliance(normalized.get("COMPLIANCE", "")),
                "status": normalized.get("STATUS", "").upper(),
                "status_extended": normalized.get("STATUS_EXTENDED", ""),
                "severity": normalized.get("SEVERITY", "informational").lower(),
                "service": normalized.get("SERVICE_NAME", ""),
                "resource_type": normalized.get("RESOURCE_TYPE", ""),
                "resource_id": normalized.get("RESOURCE_UID", ""),
                "resource_name": normalized.get("RESOURCE_NAME", ""),
                "resource_tags": _parse_delimited_mapping(
                    normalized.get("RESOURCE_TAGS", ""), "="
                ),
                "region": normalized.get("REGION", ""),
                "description": normalized.get("DESCRIPTION", ""),
                "risk": normalized.get("RISK", ""),
                "remediation": normalized.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
                "remediation_url": normalized.get("REMEDIATION_RECOMMENDATION_URL", ""),
            }
        )
    return findings


def _summarize_findings(findings: list[dict[str, str]]) -> dict[str, Any]:
    failed = [finding for finding in findings if finding["status"] == "FAIL"]
    errored = [finding for finding in findings if finding["status"] == "ERROR"]
    skipped = [finding for finding in findings if finding["status"] in {"SKIP", "SKIPPED"}]
    manual = [finding for finding in findings if finding["status"] == "MANUAL"]
    muted = [finding for finding in findings if finding["status"] in {"MUTED", "SUPPRESSED"}]
    not_applicable = [
        finding
        for finding in findings
        if finding["status"] in {"NOT_APPLICABLE", "NOTAPPLICABLE", "N/A"}
    ]
    passed = [finding for finding in findings if finding["status"] == "PASS"]
    categorized = (
        len(failed)
        + len(errored)
        + len(skipped)
        + len(manual)
        + len(muted)
        + len(not_applicable)
        + len(passed)
    )
    summary: dict[str, Any] = {
        "total_checks": len(findings),
        "failed_checks": len(failed),
        "passed_checks": len(passed),
        "manual_checks": len(manual),
        "muted_checks": len(muted),
        "not_applicable_checks": len(not_applicable),
        "errored_checks": len(errored),
        "skipped_checks": len(skipped),
        "checks_unavailable": len(errored) + len(skipped),
        "other_checks": len(findings) - categorized,
        "severity_counts": {severity: 0 for severity in sorted(FINDING_SEVERITIES)},
    }
    for finding in failed:
        severity = finding.get("severity", "informational")
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
    if provider == "aws" and scope.get("regions"):
        command.extend(["--region", *scope["regions"]])
    elif provider == "aws" and scope.get("region"):
        command.extend(["--region", scope["region"]])
    elif provider == "azure":
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


def _update_progress(
    db,
    scan_id: str,
    user_id: str,
    stage: str,
    message: str,
    output_bytes: int | None = None,
) -> dict[str, Any] | None:
    scan = db.query(CloudSecurityAssessment).filter(
        CloudSecurityAssessment.scan_id == scan_id,
        CloudSecurityAssessment.user_id == user_id,
    ).first()
    if scan is None:
        logger.error("Cloud assessment record %s disappeared during %s.", scan_id, stage)
        return None

    summary = dict(scan.summary) if isinstance(scan.summary, dict) else {}
    progress = dict(summary.get("progress") or {})
    events = list(progress.get("events") or [])
    updated_at = datetime.now(timezone.utc).isoformat()
    if not events or events[-1].get("stage") != stage or events[-1].get("message") != message:
        events.append({"stage": stage, "message": message, "timestamp": updated_at})
        events = events[-20:]
    progress.update(
        {
            "stage": stage,
            "message": message,
            "updated_at": updated_at,
            "events": events,
        }
    )
    if output_bytes is not None:
        progress["output_bytes"] = output_bytes
    summary["progress"] = progress
    scan.summary = summary
    db.commit()
    logger.info("Cloud assessment %s: %s - %s", scan_id, stage, message)
    return progress


def _run_prowler_with_progress(
    command: list[str],
    process_env: dict[str, str],
    log_path: Path,
    on_progress,
) -> int:
    started_at = time.monotonic()
    last_update_at = started_at
    last_output_size = 0
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            command,
            env=process_env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            while process.poll() is None:
                elapsed = time.monotonic() - started_at
                if elapsed >= PROWLER_TIMEOUT_SECONDS:
                    raise subprocess.TimeoutExpired(command, PROWLER_TIMEOUT_SECONDS)

                output_size = log_path.stat().st_size
                now = time.monotonic()
                if output_size != last_output_size or now - last_update_at >= PROGRESS_UPDATE_SECONDS:
                    output_kb = output_size // 1024
                    message = (
                        f"Prowler is running; {output_kb} KB of scanner output received."
                        if output_size
                        else "Prowler is running; waiting for results from the cloud provider."
                    )
                    on_progress(message, output_size)
                    last_output_size = output_size
                    last_update_at = now
                time.sleep(PROGRESS_POLL_SECONDS)
            return process.wait()
        except BaseException:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise


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
        _update_progress(
            db,
            scan_id,
            user_id,
            "starting",
            "Preparing the scanner and cloud assessment.",
        )
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
            _update_progress(
                db,
                scan_id,
                user_id,
                "scanning",
                "Prowler is checking the selected cloud scope.",
            )
            returncode = _run_prowler_with_progress(
                command,
                process_env,
                log_path,
                lambda message, output_bytes: _update_progress(
                    db,
                    scan_id,
                    user_id,
                    "scanning",
                    message,
                    output_bytes,
                ),
            )
            _update_progress(
                db,
                scan_id,
                user_id,
                "collecting_results",
                "Prowler finished; collecting the generated assessment report.",
            )
            findings = _load_csv_findings(output_directory)
            if returncode != 0:
                logger.info(
                    "Prowler exited with status %s after producing a report for assessment %s.",
                    returncode,
                    scan_id,
                )

        scan = db.query(CloudSecurityAssessment).filter(
            CloudSecurityAssessment.scan_id == scan_id,
            CloudSecurityAssessment.user_id == user_id,
        ).first()
        if scan is None:
            logger.error("Cloud assessment record %s disappeared before completion.", scan_id)
            return
        scan.status = "completed"
        scan.findings = findings
        summary = _summarize_findings(findings)
        previous_summary = scan.summary if isinstance(scan.summary, dict) else {}
        summary["progress"] = dict(previous_summary.get("progress") or {})
        if previous_summary.get("account_id"):
            summary["account_id"] = previous_summary["account_id"]
        scan.summary = summary
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Cloud assessment %s completed with %s checks.", scan_id, len(findings))
    except subprocess.TimeoutExpired:
        logger.warning("Cloud assessment %s exceeded the one-hour time limit.", scan_id)
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
        summary = dict(scan.summary) if isinstance(scan.summary, dict) else {}
        progress = dict(summary.get("progress") or {})
        updated_at = datetime.now(timezone.utc).isoformat()
        events = list(progress.get("events") or [])
        events.append({"stage": "failed", "message": message, "timestamp": updated_at})
        progress.update(
            {
                "stage": "failed",
                "message": message,
                "updated_at": updated_at,
                "events": events[-20:],
            }
        )
        summary["progress"] = progress
        scan.summary = summary
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()


def request_credentials(request: CloudAssessmentRequest) -> tuple[str, dict[str, Any], dict[str, str]]:
    if isinstance(request, AwsAssessmentRequest):
        credentials = {
            "access_key_id": request.access_key_id,
            "secret_access_key": request.secret_access_key.get_secret_value(),
            "session_token": request.session_token.get_secret_value() if request.session_token else "",
        }
        regions = request.aws_regions or (
            [request.aws_region] if request.aws_region else []
        )
        if len(regions) == 1:
            scope = {"region": regions[0]}
        elif regions:
            scope = {"regions": sorted(regions)}
        else:
            scope = {}
        return "aws", scope, credentials
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
