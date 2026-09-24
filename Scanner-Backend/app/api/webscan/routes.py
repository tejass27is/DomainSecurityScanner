"""Acunetix web-application scanning API.

The create endpoint is intentionally non-blocking: it registers the target and
starts the scan in Acunetix, stores the returning ids against a ``web_scans``
row, and pushes a job onto the ``webscan_queue``. A Go worker owns the slow part
(polling Acunetix until the scan finishes) and posts the findings back to
``/webhooks/webscan/result``.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from io import BytesIO
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Image, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.api.scanner.service import _normalize_domain_for_match
from app.api.webscan.acunetix import AcunetixClient, AcunetixError, resolve_base_url
from app.api.webscan.schemas import WebScanCreateRequest, WebScanDetail, WebScanListItem
from app.core.middleware import require_webscan_access, require_webscan_owner
from app.core.redis_queue import RedisClient
from app.core.websocket_manager import ws_manager
from app.db.base import get_db
from app.db.models import Organization, User, WebScan

router = APIRouter(prefix="/webscan", tags=["webscan"])
logger = logging.getLogger(__name__)

redis_client = RedisClient()

#: Redis list the ``worker-webscan`` process blocks on.
WEBSCAN_QUEUE = "webscan_queue"

#: Statuses that mean "the scan is no longer moving".
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", re.IGNORECASE)
_DEFAULT_PORTS = {("http", 80), ("https", 443)}


# ─── URL helpers ──────────────────────────────────────────────────────────────

def normalize_target_url(raw: str) -> tuple[str, str]:
    """Validate + normalize a scan target.

    Adds a scheme when missing, lowercases the host, drops the fragment and any
    trailing slash, and drops a redundant default port. Returns
    ``(normalized_url, host)``.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="A URL is required.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parts = urlsplit(candidate)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only http:// and https:// URLs can be scanned.")
    if parts.username or parts.password:
        raise HTTPException(status_code=400, detail="URLs containing credentials are not accepted.")
    if not parts.hostname:
        raise HTTPException(status_code=400, detail="That does not look like a valid URL.")

    try:
        port = parts.port
    except ValueError:
        raise HTTPException(status_code=400, detail="That does not look like a valid URL.")

    host = parts.hostname.strip().lower().rstrip(".")
    if not _HOST_RE.match(host) or ".." in host:
        raise HTTPException(status_code=400, detail="That does not look like a valid URL.")

    netloc = host
    if port and (scheme, port) not in _DEFAULT_PORTS:
        netloc = f"{host}:{port}"

    path = (parts.path or "").rstrip("/")
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    return normalized, host


def _host_belongs_to_org(host: str, raw_org_domains) -> bool:
    """True when ``host`` is one of the org's registered domains (or a subdomain).

    Subdomains are allowed because web-application scanning normally targets a
    specific app host (``app.example.com``) while the account holds the parent
    domain.
    """
    if not isinstance(raw_org_domains, list):
        raw_org_domains = [raw_org_domains] if raw_org_domains else []

    owned = {
        _normalize_domain_for_match(str(domain))
        for domain in raw_org_domains
        if str(domain).strip()
    }
    owned.discard("")

    host_norm = _normalize_domain_for_match(host.split(":", 1)[0])
    if not host_norm:
        return False

    return any(
        host_norm == domain or host_norm.endswith(f".{domain}")
        for domain in owned
    )


# ─── Serialization ────────────────────────────────────────────────────────────

def _to_list_item(record: WebScan) -> dict:
    return {
        "scan_id": str(record.scan_id),
        "target_url": record.target_url,
        "target_host": record.target_host,
        "scan_type": record.scan_type or "dynamic",
        "status": record.status,
        "progress": record.progress or 0,
        "current_stage": record.current_stage,
        "message": record.message,
        "total_findings": record.total_findings or 0,
        "unique_urls": record.unique_urls or 0,
        "risk_score": record.risk_score or 0,
        "severity": record.severity or "none",
        "severity_distribution": record.severity_distribution or {},
        "scan_profile": record.scan_profile,
        "criticality": record.criticality,
        "authentication_required": bool(record.authentication_required),
        "auth_method": record.auth_method,
        "login_url": record.login_url,
        "auth_username": record.auth_username,
        "auth_profile_id": record.auth_profile_id,
        "mfa_instructions": record.mfa_instructions,
        "auth_details": record.auth_details,
        "login_sequence": record.login_sequence,
        "acunetix_scan_id": record.acunetix_scan_id,
        "error_message": record.error_message,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "created_at": record.created_at,
    }


def _to_detail(record: WebScan) -> dict:
    return {
        **_to_list_item(record),
        "findings": record.findings or [],
        "summary": record.summary or {},
    }


def _get_org_scan_or_404(db: Session, scan_id: str, org_id: str | None) -> WebScan:
    try:
        parsed = uuid.UUID(str(scan_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=404, detail="Web scan not found.")

    record = db.query(WebScan).filter(
        WebScan.scan_id == parsed,
        WebScan.org_id == org_id,
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Web scan not found.")
    return record


def _normalize_repo_url(raw: str) -> str:
    """Return a normalized repository URL for Semgrep static scanning."""
    candidate = (raw or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="A repository URL is required for static scans.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Static scans require an http:// or https:// repository URL.")
    if not parts.netloc:
        raise HTTPException(status_code=400, detail="That does not look like a valid repository URL.")
    return candidate.rstrip("/")


def _semgrep_severity_label(value: str | None) -> str:
    raw = (value or "").strip().upper()
    if raw in {"CRITICAL", "ERROR"}:
        return "critical"
    if raw in {"HIGH", "WARNING"}:
        return "high"
    if raw == "MEDIUM":
        return "medium"
    if raw == "LOW":
        return "low"
    return "info"


# Severity weights for the 0-100 risk index (same convention as VAPT).
_SEVERITY_SCALE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _compute_risk_score(findings: list[dict]) -> int:
    """Transparent 0-100 risk index, matching the VAPT scoring convention.

    ``score = min(100, 18 * worst_severity + 10 * average_density)`` — a raw
    count of findings must never exceed 100, no matter how many are reported.
    """
    if not findings:
        return 0

    weights = [_SEVERITY_SCALE.get(str(f.get("severity") or "info").lower(), 0) for f in findings]
    worst = max(weights)
    average_density = sum(weights) / len(weights)
    return min(100, round(18 * worst + 10 * average_density))


def _semgrep_payload_to_findings(payload: dict) -> list[dict]:
    findings: list[dict] = []
    for index, result in enumerate(payload.get("results") or []):
        if not isinstance(result, dict):
            continue

        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        path = str(result.get("path") or "repository").strip() or "repository"
        repo_marker = f"{os.sep}repo{os.sep}"
        if repo_marker in path:
            path = path.split(repo_marker, 1)[1]
        start = result.get("start") or {}
        end = result.get("end") or {}
        start_line = start.get("line")
        end_line = end.get("line") or start_line
        line = str(start_line) if start_line else ""
        line_range = line if not end_line or end_line == start_line else f"{line}-{end_line}"
        severity_label = _semgrep_severity_label(str(extra.get("severity") or metadata.get("severity") or "info"))
        message = str(extra.get("message") or "Semgrep finding").strip() or "Semgrep finding"
        rule_id = str(result.get("check_id") or metadata.get("rule_id") or f"semgrep-{index + 1}").strip()

        findings.append({
            "id": f"semgrep-{index + 1}",
            "title": rule_id,
            "severity": severity_label,
            "severity_label": severity_label,
            "description": message,
            "solution": "Review the flagged code path and apply the recommended remediation for this rule.",
            "references": [str(metadata.get("source") or "")] if metadata.get("source") else [],
            "cwe": metadata.get("cwe") or metadata.get("cwe_id") or "",
            "affected_url": path,
            "affected_hosts": [path],
            "file": path,
            "line": line,
            "start_line": start_line,
            "end_line": end_line,
            "line_range": line_range,
            "host": path,
            "source": "semgrep",
            "plugin_id": rule_id,
            "plugin_family": "Semgrep",
            "category": "static-analysis",
            "status": "pending",
            "evidence": f"{rule_id} at {path}",
        })
    return findings


#: Upper bounds for uploaded archives, so a zip bomb or an accidental huge
#: upload cannot fill the disk of the scanning host.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024


def _semgrep_scan_directory(scan_root: str) -> dict:
    """Run Semgrep over an on-disk directory and normalize the findings."""
    if shutil.which("semgrep") is None:
        raise RuntimeError("semgrep is not installed or not on PATH. Install semgrep before running static scans.")

    scan = subprocess.run(
        ["semgrep", "scan", "--json", "--config", "auto", "--metrics", "auto", scan_root],
        capture_output=True,
        text=True,
        check=False,
    )
    if scan.returncode not in {0, 1}:
        stderr = (scan.stderr or scan.stdout or "").strip()
        raise RuntimeError(f"Semgrep scan failed: {stderr or 'semgrep exited with an error'}")

    payload = json.loads(scan.stdout or "{}") if scan.stdout.strip() else {}
    findings = _semgrep_payload_to_findings(payload)

    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity in severity_distribution:
            severity_distribution[severity] += 1

    risk_score = _compute_risk_score(findings)

    return {
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "severity_distribution": severity_distribution,
            "risk_score": risk_score,
        },
    }


def _authenticated_clone_url(repo_url: str, token: str | None) -> str:
    """Embed a private-repo token into an HTTPS clone URL.

    ``x-access-token`` is the username GitHub documents for token auth; it also
    works for GitLab/Bitbucket HTTPS clones. The token is never logged or stored.
    """
    token = (token or "").strip()
    if not token:
        return repo_url

    parts = urlsplit(repo_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return repo_url

    netloc = f"x-access-token:{quote(token, safe='')}@{parts.hostname}"
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def _redact_secret(text: str, *secrets: str | None) -> str:
    """Strip secrets from git/CLI output before it reaches a log or an error."""
    redacted = text or ""
    for secret in secrets:
        secret = (secret or "").strip()
        if not secret:
            continue
        redacted = redacted.replace(secret, "***")
        redacted = redacted.replace(quote(secret, safe=""), "***")
    return redacted


def _run_semgrep_static_scan(repo_url: str, branch: str | None = None, token: str | None = None) -> dict:
    """Clone a public/private Git repository and scan it with Semgrep."""
    repo_url = _normalize_repo_url(repo_url)
    clone_url = _authenticated_clone_url(repo_url, token)

    temp_root = tempfile.mkdtemp(prefix="shieldstat-semgrep-")
    clone_dir = os.path.join(temp_root, "repo")
    try:
        clone_args = ["git", "clone", "--depth", "1"]
        if branch and str(branch).strip():
            clone_args += ["--branch", str(branch).strip()]
        clone_args += [clone_url, clone_dir]

        clone = subprocess.run(
            clone_args,
            capture_output=True,
            text=True,
            check=False,
        )
        if clone.returncode != 0:
            stderr = _redact_secret((clone.stderr or clone.stdout or "").strip(), token)
            raise RuntimeError(f"Could not clone repository: {stderr or 'git clone failed'}")

        return _semgrep_scan_directory(clone_dir)
    finally:
        try:
            shutil.rmtree(temp_root, ignore_errors=True)
        except Exception:
            logger.debug("Could not remove temporary semgrep repo directory %s", temp_root, exc_info=True)


def _safe_extract_zip(file_bytes: bytes, dest_dir: str) -> None:
    """Extract a ZIP into ``dest_dir``, rejecting path traversal and zip bombs."""
    try:
        archive = zipfile.ZipFile(BytesIO(file_bytes))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="That file is not a valid ZIP archive.") from exc

    dest_root = os.path.realpath(dest_dir)
    total_uncompressed = 0

    with archive:
        for member in archive.infolist():
            name = (member.filename or "").replace("\\", "/")
            if not name or name.startswith("/") or ".." in name.split("/"):
                raise HTTPException(status_code=400, detail="The ZIP archive contains unsafe file paths.")

            target = os.path.realpath(os.path.join(dest_root, name))
            if target != dest_root and not target.startswith(dest_root + os.sep):
                raise HTTPException(status_code=400, detail="The ZIP archive contains unsafe file paths.")

            total_uncompressed += max(0, int(member.file_size or 0))
            if total_uncompressed > MAX_EXTRACTED_BYTES:
                raise HTTPException(status_code=413, detail="The ZIP archive is too large to scan.")

        archive.extractall(dest_root)


def _run_semgrep_static_upload(file_bytes: bytes, filename: str) -> dict:
    """Scan an uploaded ZIP archive (a codebase snapshot) with Semgrep."""
    if not file_bytes:
        raise HTTPException(status_code=400, detail="The uploaded archive is empty.")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="The uploaded archive is too large to scan.")

    temp_root = tempfile.mkdtemp(prefix="shieldstat-semgrep-")
    repo_dir = os.path.join(temp_root, "repo")
    os.makedirs(repo_dir, exist_ok=True)
    try:
        _safe_extract_zip(file_bytes, repo_dir)
        if not os.listdir(repo_dir):
            raise HTTPException(status_code=400, detail="The uploaded ZIP archive is empty.")
        logger.info("Running Semgrep on uploaded archive %s", filename)
        return _semgrep_scan_directory(repo_dir)
    finally:
        try:
            shutil.rmtree(temp_root, ignore_errors=True)
        except Exception:
            logger.debug("Could not remove temporary semgrep upload directory %s", temp_root, exc_info=True)


def _fail_static_scan(db: Session, record: WebScan, error: str) -> None:
    """Mark a static web-scan record as failed and persist the reason."""
    record.status = "failed"
    record.message = "Static repository scan failed"
    record.error_message = error
    record.finished_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    db.refresh(record)


def _finalize_static_scan(db: Session, record: WebScan, result: dict) -> None:
    """Apply a completed Semgrep result to a web-scan record."""
    findings = result.get("findings") or []
    summary = result.get("summary") or {}
    record.status = "completed"
    record.progress = 100
    record.current_stage = "completed"
    record.message = "Static repository scan completed"
    record.findings = findings
    record.summary = summary
    record.total_findings = len(findings)
    record.unique_urls = len({f.get("affected_url") for f in findings if f.get("affected_url")})
    record.risk_score = int(summary.get("risk_score") or 0)
    record.severity = (
        "high" if any(f.get("severity") in {"critical", "high"} for f in findings)
        else "medium" if any(f.get("severity") == "medium" for f in findings)
        else "low" if findings
        else "none"
    )
    record.severity_distribution = summary.get("severity_distribution") or {}
    record.started_at = datetime.now(timezone.utc)
    record.finished_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    db.refresh(record)


def _build_static_webscan_pdf(record: WebScan) -> bytes:
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#53154d"), spaceAfter=8)
    small_style = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=7.5, leading=9)
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], textColor=colors.HexColor("#53154d"), spaceBefore=10, spaceAfter=6)

    document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=14 * mm, leftMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    story = [
        Paragraph("Static Repository Security Scan", title_style),
        Paragraph(f"<b>Repository:</b> {record.target_url}", styles["BodyText"]),
        Paragraph(f"<b>Status:</b> {record.status.title()} &nbsp;&nbsp; <b>Generated:</b> {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}", small_style),
        Spacer(1, 8),
    ]

    distribution = record.severity_distribution or {}
    summary_data = [
        ["Total findings", "Critical", "High", "Medium", "Low", "Info", "Risk score"],
        [str(record.total_findings or 0), str(distribution.get("critical", 0)), str(distribution.get("high", 0)), str(distribution.get("medium", 0)), str(distribution.get("low", 0)), str(distribution.get("info", 0)), str(record.risk_score or 0)],
    ]
    summary_table = Table(summary_data, colWidths=[25 * mm] * 7)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8eaf3")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#53154d")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d9cbd8")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([summary_table, Spacer(1, 10), Paragraph("Detailed Findings", heading_style)])

    rows = [["Severity", "Rule", "File", "Line", "CWE", "Recommendation"]]
    for finding in record.findings or []:
        rows.append([
            Paragraph(str(finding.get("severity_label") or finding.get("severity") or "Info").upper(), small_style),
            Paragraph(str(finding.get("title") or finding.get("plugin_id") or "Finding"), small_style),
            Paragraph(str(finding.get("file") or finding.get("affected_url") or "-"), small_style),
            Paragraph(str(finding.get("line_range") or finding.get("line") or "-"), small_style),
            Paragraph(str(finding.get("cwe") or "-"), small_style),
            Paragraph(str(finding.get("description") or finding.get("solution") or "Review this finding."), small_style),
        ])

    findings_table = Table(rows, colWidths=[18 * mm, 38 * mm, 45 * mm, 14 * mm, 22 * mm, 47 * mm], repeatRows=1)
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8eaf3")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#53154d")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d9cbd8")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(findings_table)
    document.build(story)
    return buffer.getvalue()


_DYNAMIC_REPORT_TYPES = {
    "developer": "Developer Report",
    "executive": "Executive Summary Report",
    "quick": "Quick Report",
    "affected": "Affected Items Report",
}


def _report_logo():
    logo_path = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "isecurify_logo.png")
    if not os.path.exists(logo_path):
        return Spacer(1, 1)
    return Image(logo_path, width=42 * mm, height=11 * mm, kind="proportional")


def _report_value(value, fallback="Not provided by Acunetix"):
    if value is None or value == "" or value == [] or value == {}:
        return fallback
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, default=str)
    return str(value)


def _suggested_action(finding):
    severity = str(finding.get("severity_label") or finding.get("severity") or "info").lower()
    if severity == "critical":
        return "Fix Immediately"
    if severity == "high":
        return "Prioritize Remediation"
    if severity == "medium":
        return "Plan Remediation"
    if severity == "low":
        return "Review and Schedule"
    return "Confirm and Monitor"


def _build_dynamic_webscan_pdf(record: WebScan, report_type: str) -> bytes:
    report_type = report_type if report_type in _DYNAMIC_REPORT_TYPES else "developer"
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("DynamicTitle", parent=styles["Title"], textColor=colors.HexColor("#53154d"), spaceAfter=6)
    heading_style = ParagraphStyle("DynamicHeading", parent=styles["Heading2"], textColor=colors.HexColor("#53154d"), spaceBefore=10, spaceAfter=6)
    small_style = ParagraphStyle("DynamicSmall", parent=styles["BodyText"], fontSize=8, leading=10)
    body_style = ParagraphStyle("DynamicBody", parent=styles["BodyText"], fontSize=9, leading=12)
    document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=14 * mm, leftMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    distribution = record.severity_distribution or {}
    findings = record.findings or []
    summary = record.summary or {}
    scan_metadata = summary.get("scan_metadata") or {}
    reconnaissance = summary.get("reconnaissance") or {}
    if not scan_metadata.get("duration") and record.started_at and record.finished_at:
        scan_metadata["duration"] = str(record.finished_at - record.started_at)
    story = [
        _report_logo(),
        Paragraph(_DYNAMIC_REPORT_TYPES[report_type], title_style),
        Paragraph(f"<b>Target:</b> {record.target_url}", body_style),
        Paragraph(f"<b>Status:</b> {record.status.title()} &nbsp;&nbsp; <b>Generated:</b> {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}", small_style),
        Spacer(1, 10),
    ]

    summary_rows = [
        ["Findings", "Critical", "High", "Medium", "Low", "Risk score"],
        [str(record.total_findings or 0), str(distribution.get("critical", 0)), str(distribution.get("high", 0)), str(distribution.get("medium", 0)), str(distribution.get("low", 0)), str(record.risk_score or 0)],
    ]
    summary_table = Table(summary_rows, colWidths=[31 * mm] * 6)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8eaf3")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#53154d")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b8c9d8")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([summary_table, Spacer(1, 10)])

    if report_type == "executive":
        story.extend([
            Paragraph("Executive Overview", heading_style),
            Paragraph(
                f"This assessment identified <b>{record.total_findings or 0}</b> vulnerability finding(s) across "
                f"<b>{record.unique_urls or 0}</b> affected URL(s). The overall recorded risk score is "
                f"<b>{record.risk_score or 0}/100</b>. Remediation should begin with critical and high severity findings.",
                body_style,
            ),
            Paragraph("Scan Metadata", heading_style),
            Paragraph(
                f"<b>Scan target:</b> {_report_value(scan_metadata.get('target_url') or record.target_url)}<br/>"
                f"<b>Scan time:</b> {_report_value(scan_metadata.get('start_time') or scan_metadata.get('start_date') or record.started_at)}<br/>"
                f"<b>Duration:</b> {_report_value(scan_metadata.get('duration'))}<br/>"
                f"<b>Description:</b> {_report_value(scan_metadata.get('description'))}<br/>"
                f"<b>Total requests:</b> {_report_value(scan_metadata.get('total_requests') or scan_metadata.get('requests_count'))}<br/>"
                f"<b>Average speed:</b> {_report_value(scan_metadata.get('average_speed'))}<br/>"
                f"<b>Tags:</b> {_report_value(scan_metadata.get('tags'))}<br/>"
                f"<b>Risk level:</b> {_report_value(scan_metadata.get('risk_level') or record.severity)}",
                body_style,
            ),
            Paragraph("Suggested Actions", heading_style),
        ])
        action_rows = [["Severity", "Vulnerability", "Affected URL", "Suggested Action"]]
        for finding in findings:
            action_rows.append([
                str(finding.get("severity_label") or finding.get("severity") or "Info").upper(),
                str(finding.get("title") or "Finding"),
                str(finding.get("affected_url") or "-"),
                _suggested_action(finding),
            ])
        story.append(Table(action_rows, colWidths=[25 * mm, 55 * mm, 70 * mm, 30 * mm], repeatRows=1, style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8eaf3")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#53154d")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b8c9d8")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])))
        story.extend([
            Paragraph("Compliance Summary", heading_style),
            Paragraph(_report_value(summary.get("compliance")), body_style),
        ])
    elif report_type == "quick":
        story.extend([
            Paragraph("Quick Overview", heading_style),
            Paragraph(f"<b>{record.total_findings or 0}</b> finding(s), <b>{record.unique_urls or 0}</b> affected URL(s), risk score <b>{record.risk_score or 0}/100</b>.", body_style),
        ])
    elif report_type == "affected":
        story.append(Paragraph("Affected Items", heading_style))
        rows = [["Severity", "Vulnerability", "Affected URL", "Evidence"]]
        for finding in findings:
            rows.append([
                Paragraph(str(finding.get("severity_label") or finding.get("severity") or "Info").upper(), small_style),
                Paragraph(str(finding.get("title") or "Finding"), small_style),
                Paragraph(str(finding.get("affected_url") or (finding.get("affected_hosts") or ["-"])[0]), small_style),
                Paragraph(str(finding.get("affected_detail") or finding.get("evidence") or "-"), small_style),
            ])
        story.append(Table(rows, colWidths=[24 * mm, 48 * mm, 70 * mm, 38 * mm], repeatRows=1, style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8eaf3")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#53154d")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b8c9d8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ])))
    else:
        story.append(Paragraph("Technical Findings", heading_style))
        rows = [["Severity", "Finding", "Affected URL", "Description", "Recommendation"]]
        for finding in findings:
            rows.append([
                Paragraph(str(finding.get("severity_label") or finding.get("severity") or "Info").upper(), small_style),
                Paragraph(str(finding.get("title") or "Finding"), small_style),
                Paragraph(str(finding.get("affected_url") or (finding.get("affected_hosts") or ["-"])[0]), small_style),
                Paragraph(str(finding.get("description") or "-"), small_style),
                Paragraph(str(finding.get("solution") or "Review and remediate the affected component."), small_style),
            ])
        story.append(Table(rows, colWidths=[20 * mm, 38 * mm, 43 * mm, 47 * mm, 32 * mm], repeatRows=1, style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8eaf3")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#53154d")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b8c9d8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.2),
        ])))
        for index, finding in enumerate(findings, start=1):
            story.extend([
                Paragraph(f"{index}. {finding.get('title') or 'Finding'}", heading_style),
                Paragraph(
                    f"<b>Severity:</b> {str(finding.get('severity_label') or finding.get('severity') or 'Info').upper()} "
                    f"&nbsp;&nbsp; <b>CWE:</b> {finding.get('cwe') or '-'} "
                    f"&nbsp;&nbsp; <b>CVSS:</b> {finding.get('cvss_score') or '-'} "
                    f"&nbsp;&nbsp; <b>Confidence:</b> {finding.get('confidence') or '-'}%",
                    small_style,
                ),
                Paragraph(f"<b>Affected URL:</b> {finding.get('affected_url') or '-'}", small_style),
                Paragraph(
                    f"<b>Acunetix vulnerability ID:</b> {_report_value(finding.get('vuln_id'))} &nbsp;&nbsp; "
                    f"<b>Result ID:</b> {_report_value(finding.get('result_id'))}<br/>"
                    f"<b>Target ID:</b> {_report_value(finding.get('target_id'))} &nbsp;&nbsp; "
                    f"<b>Status:</b> {_report_value(finding.get('status'))}<br/>"
                    f"<b>Last seen:</b> {_report_value(finding.get('last_seen'))} &nbsp;&nbsp; "
                    f"<b>Port:</b> {_report_value(finding.get('port'))} &nbsp;&nbsp; "
                    f"<b>Protocol:</b> {_report_value(finding.get('protocol'))} &nbsp;&nbsp; "
                    f"<b>Service:</b> {_report_value(finding.get('service'))}",
                    small_style,
                ),
                Paragraph(f"<b>Description:</b> {finding.get('description') or '-'}", body_style),
            ])
            for label, key in (
                ("HTTP Request", "http_request"),
                ("Request Headers", "request_headers"),
                ("Request Body", "request_body"),
                ("HTTP Response", "http_response"),
                ("Response Headers", "response_headers"),
                ("Response Body", "response_body"),
                ("Evidence", "evidence"),
            ):
                value = str(finding.get(key) or "").strip()
                if key == "evidence" and value and finding.get("affected_detail"):
                    value = f"Affected parameter/detail: {finding.get('affected_detail')}\nEvidence: {value}"
                if value:
                    story.extend([
                        Paragraph(f"<b>{label}</b>", small_style),
                        Preformatted(value, small_style),
                        Spacer(1, 4),
                    ])
            story.append(Paragraph(f"<b>Recommendation:</b> {finding.get('solution') or 'Review and remediate the affected component.'}", body_style))
            story.extend([
                Paragraph(f"<b>CVSS vector:</b> {_report_value(finding.get('cvss_vector'))}", small_style),
                Paragraph(f"<b>CVEs:</b> {_report_value(finding.get('cves'))}", small_style),
                Paragraph(f"<b>References:</b> {_report_value(finding.get('references'))}", small_style),
            ])
        story.append(Paragraph("Reconnaissance", heading_style))
        for label, key in (
            ("Files with long response times", "long_response_times"),
            ("External links", "external_links"),
            ("Email addresses found", "emails"),
            ("Client-side scripts", "client_side_scripts"),
            ("External hosts", "external_hosts"),
        ):
            story.extend([
                Paragraph(f"<b>{label}</b>", small_style),
                Preformatted(_report_value(reconnaissance.get(key)), small_style),
                Spacer(1, 4),
            ])
        story.extend([
            Paragraph("Best Practice Recommendations", heading_style),
            Paragraph(_report_value(summary.get("best_practices")), body_style),
        ])

    document.build(story)
    return buffer.getvalue()


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/scans", response_model=WebScanDetail)
async def create_web_scan(
    request: WebScanCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_webscan_owner),
):
    """Create an Acunetix scan for ``url`` and queue the polling worker."""
    if not user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization.")

    scan_mode = str(request.mode or "dynamic").strip().lower()
    if scan_mode not in {"dynamic", "static"}:
        raise HTTPException(status_code=400, detail="Scan mode must be either 'dynamic' or 'static'.")

    target_url, target_host = normalize_target_url(request.url)

    if scan_mode == "dynamic":
        org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found.")

        if not _host_belongs_to_org(target_host, org.domain):
            logger.warning(
                "SECURITY: web scan attempt for unregistered host '%s' by org '%s'",
                target_host,
                user.org_id,
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    f"'{target_host}' is not registered to this account. Add the domain "
                    "to your account before scanning it."
                ),
            )

    # Don't stack scans of the same URL — Acunetix would just queue them.
    in_flight = db.query(WebScan).filter(
        WebScan.org_id == user.org_id,
        WebScan.target_url == target_url,
        WebScan.status.in_(["pending", "running"]),
    ).first()
    if in_flight:
        return _to_detail(in_flight)

    if scan_mode == "static":
        branch_name = (request.branch or "").strip()
        if not target_url:
            raise HTTPException(status_code=400, detail="A repository URL is required for static scans.")
        if branch_name and re.fullmatch(r"[A-Za-z0-9._/-]+", branch_name) is None:
            raise HTTPException(status_code=400, detail="Repository branch name is invalid.")
        if request.repo_visibility == "private" and not (request.repo_token or "").strip():
            raise HTTPException(
                status_code=400,
                detail="A repository token is required to scan a private repository.",
            )

    requested_profile = (request.scan_profile or request.profile_id or "").strip() if scan_mode == "dynamic" else ""
    requested_criticality = request.criticality if scan_mode == "dynamic" else "medium"
    requested_auth = bool(request.authentication_required) if scan_mode == "dynamic" else False
    requested_auth_method = (request.auth_method or "").strip() if scan_mode == "dynamic" else None
    requested_login_url = (request.login_url or "").strip() if scan_mode == "dynamic" else None
    requested_auth_username = (request.auth_username or "").strip() if scan_mode == "dynamic" else None
    requested_auth_password = (request.auth_password or "").strip() if scan_mode == "dynamic" else None
    requested_auth_header_name = (request.auth_header_name or "").strip() if scan_mode == "dynamic" else None
    requested_auth_token = (request.auth_token or "").strip() if scan_mode == "dynamic" else None
    requested_cookie_name = (request.session_cookie_name or "").strip() if scan_mode == "dynamic" else None
    requested_cookie_value = (request.session_cookie_value or "").strip() if scan_mode == "dynamic" else None
    requested_auth_profile_id = (request.auth_profile_id or "").strip() if scan_mode == "dynamic" else None
    requested_mfa_instructions = (request.mfa_instructions or "").strip() if scan_mode == "dynamic" else None
    requested_auth_details = (request.auth_details or "").strip() if scan_mode == "dynamic" else None
    requested_login_sequence = (request.login_sequence or "").strip() if scan_mode == "dynamic" else None
    # Private-repo token: used for the clone, never persisted or logged.
    requested_repo_token = (request.repo_token or "").strip() if scan_mode == "static" else None

    record = WebScan(
        org_id=user.org_id,
        user_id=user.user_id,
        target_url=target_url,
        target_host=target_host,
        scan_type=scan_mode,
        status="pending",
        progress=0,
        current_stage="queued",
        message="Submitting scan to Acunetix" if scan_mode == "dynamic" else "Submitting static repository scan",
        profile_id=(request.profile_id if scan_mode == "dynamic" else None),
        scan_profile=request.scan_profile.strip() if request.scan_profile else None,
        criticality=("medium" if request.criticality == "normal" else request.criticality),
        authentication_required=requested_auth,
        auth_method=requested_auth_method,
        login_url=requested_login_url,
        auth_username=requested_auth_username,
        # Secret values are intentionally not persisted. They must be sent to
        # a verified Acunetix auth-configuration endpoint before use.
        auth_password=None,
        auth_header_name=requested_auth_header_name,
        auth_token=None,
        session_cookie_name=requested_cookie_name,
        session_cookie_value=None,
        auth_profile_id=requested_auth_profile_id,
        mfa_instructions=requested_mfa_instructions,
        auth_details=requested_auth_details,
        login_sequence=requested_login_sequence,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    if scan_mode == "static":
        try:
            repo_result = _run_semgrep_static_scan(
                target_url,
                branch=(request.branch or "").strip() or None,
                token=requested_repo_token,
            )
            _finalize_static_scan(db, record, repo_result)
            return _to_detail(record)
        except HTTPException:
            raise
        except Exception as exc:
            _fail_static_scan(db, record, str(exc))
            logger.error("Semgrep static scan failed for %s: %s", target_url, exc)
            raise HTTPException(status_code=500, detail=f"Static scan failed: {exc}") from exc

    # ── Ask Acunetix to create the target and start the scan ──────────────────
    try:
        with AcunetixClient() as client:
            profile_id = request.profile_id or client.resolve_profile_id(requested_profile or None)
            criticality_score = {
                "critical": 10,
                "high": 8,
                "normal": 5,
                "medium": 5,
                "low": 2,
            }.get(requested_criticality or "normal", 5)
            description = f"ShieldStat web scan requested by {user.email}"
            acunetix_target_id = client.create_target(
                target_url,
                description=description,
                criticality=criticality_score,
            )

            # Configure authentication on the target *before* the scan starts,
            # so the crawl is authenticated. Unverified methods (login sequence,
            # SSO, MFA, Auth Profile ID) return a note instead of being sent.
            auth_note = None
            if requested_auth:
                try:
                    auth_note = client.configure_authentication(
                        acunetix_target_id,
                        method=requested_auth_method or "",
                        username=requested_auth_username or "",
                        password=requested_auth_password or "",
                        token_header=requested_auth_header_name or "Authorization",
                        token_value=requested_auth_token or "",
                    )
                except AcunetixError:
                    # A mis-shaped/unsupported config must not lose the scan; the
                    # operator is told via auth_details and can set it manually.
                    logger.warning(
                        "Could not configure Acunetix authentication for %s",
                        target_url,
                        exc_info=True,
                    )
                    auth_note = (
                        "ShieldStat could not configure this authentication method on "
                        "Acunetix automatically; configure it manually in Acunetix."
                    )

            acunetix_scan_id = client.start_scan(acunetix_target_id, profile_id)
    except AcunetixError as exc:
        record.status = "failed"
        record.message = "Could not start the Acunetix scan"
        record.error_message = str(exc)
        record.finished_at = datetime.now(timezone.utc)
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.error("Acunetix scan could not be started for %s: %s", target_url, exc)
        raise HTTPException(status_code=502, detail=f"Acunetix rejected the scan: {exc}") from exc

    if auth_note:
        record.auth_details = " ".join(
            part for part in [record.auth_details, auth_note] if part
        )

    record.acunetix_target_id = acunetix_target_id
    record.acunetix_scan_id = acunetix_scan_id
    record.profile_id = profile_id
    record.status = "running"
    record.progress = 1
    record.current_stage = "queued"
    record.message = "Scan accepted by Acunetix — waiting for the worker"
    record.started_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    db.refresh(record)

    # Clear any stale signal before the worker starts so an old Redis key
    # cannot cancel a newly queued job.
    try:
        await redis_client.redis.delete(f"webscan_cancel:{record.scan_id}")
    except Exception:
        logger.warning("Could not clear stale cancel signal for web scan %s", record.scan_id, exc_info=True)

    # ── Hand the slow polling off to the Go worker ────────────────────────────
    try:
        await redis_client.PushToQueue(
            queue_name=WEBSCAN_QUEUE,
            data={
                "scan_id": str(record.scan_id),
                "org_id": user.org_id,
                "target_url": target_url,
                "acunetix_target_id": acunetix_target_id,
                "acunetix_scan_id": acunetix_scan_id,
                "profile_id": profile_id,
                "scan_profile": record.scan_profile,
                "criticality": record.criticality,
                "authentication_required": record.authentication_required,
                "auth_method": record.auth_method,
                "login_url": record.login_url,
                "auth_username": record.auth_username,
                "auth_header_name": record.auth_header_name,
                "session_cookie_name": record.session_cookie_name,
                "auth_profile_id": record.auth_profile_id,
                "mfa_instructions": record.mfa_instructions,
                "auth_details": record.auth_details,
                "login_sequence": record.login_sequence,
            },
        )
    except Exception as exc:
        record.status = "failed"
        record.message = "Could not hand the scan to a worker"
        record.error_message = f"Queue submission failed: {exc}"
        record.finished_at = datetime.now(timezone.utc)
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.error("Queue submission failed for web scan %s: %s", record.scan_id, exc)
        raise HTTPException(
            status_code=503,
            detail="The scan worker queue is unavailable. Please try again shortly.",
        ) from exc

    try:
        await ws_manager.send(user.org_id, {
            "event": "webscan_started",
            "scan_id": str(record.scan_id),
            "target_url": target_url,
            "status": record.status,
        })
    except Exception:
        logger.debug("Could not broadcast webscan_started", exc_info=True)

    return _to_detail(record)


@router.post("/scans/static/upload", response_model=WebScanDetail)
async def create_static_upload_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_webscan_owner),
):
    """Scan an uploaded ZIP snapshot of a codebase with Semgrep (static mode).

    The archive is extracted into a throwaway directory, scanned, then removed;
    nothing about the upload is persisted except the normalized findings.
    """
    if not user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization.")

    filename = os.path.basename((file.filename or "").strip()) or "archive.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip archive of the codebase.")

    payload = await file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="The uploaded archive is too large to scan.")

    record = WebScan(
        org_id=user.org_id,
        user_id=user.user_id,
        target_url=f"upload://{filename}",
        target_host=filename[:255],
        scan_type="static",
        status="pending",
        progress=0,
        current_stage="queued",
        message="Submitting static archive scan",
        criticality="medium",
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    try:
        result = _run_semgrep_static_upload(payload, filename)
        _finalize_static_scan(db, record, result)
        return _to_detail(record)
    except HTTPException:
        db.commit()
        raise
    except Exception as exc:
        _fail_static_scan(db, record, str(exc))
        logger.error("Semgrep archive scan failed for %s: %s", filename, exc)
        raise HTTPException(status_code=500, detail=f"Static scan failed: {exc}") from exc


@router.get("/scans", response_model=list[WebScanListItem])
async def list_web_scans(
    db: Session = Depends(get_db),
    user: User = Depends(require_webscan_access),
    limit: int = 50,
):
    """List the org's web scans, newest first."""
    if not user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization.")

    records = (
        db.query(WebScan)
        .filter(WebScan.org_id == user.org_id)
        .order_by(WebScan.created_at.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [_to_list_item(record) for record in records]


@router.get("/scans/{scan_id}", response_model=WebScanDetail)
async def get_web_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_webscan_access),
):
    """Fetch one web scan (including findings once it has completed)."""
    record = _get_org_scan_or_404(db, scan_id, user.org_id)
    return _to_detail(record)


@router.get("/scans/{scan_id}/report")
async def download_web_scan_report(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_webscan_access),
    report_type: str = Query("developer"),
):
    """Download an organization-scoped PDF report for a completed web scan."""
    record = _get_org_scan_or_404(db, scan_id, user.org_id)
    if record.status not in TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail="The scan must finish before a report can be downloaded.")

    if record.scan_type == "dynamic" and report_type not in _DYNAMIC_REPORT_TYPES:
        raise HTTPException(status_code=400, detail="Unknown dynamic report type.")
    filename = f"webscan-{str(record.scan_id)[:8]}-{report_type}.pdf"
    pdf = _build_dynamic_webscan_pdf(record, report_type) if record.scan_type == "dynamic" else _build_static_webscan_pdf(record)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/scans/{scan_id}/cancel", response_model=WebScanDetail)
async def cancel_web_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_webscan_owner),
):
    """Stop a running scan: signal the worker and abort it in Acunetix."""
    record = _get_org_scan_or_404(db, scan_id, user.org_id)
    if record.status in TERMINAL_STATUSES:
        return _to_detail(record)

    logger.warning(
        "Web scan cancellation requested: scan_id=%s user_id=%s org_id=%s",
        record.scan_id,
        user.user_id,
        user.org_id,
    )

    record.status = "cancelled"
    record.message = "Scan cancelled"
    record.finished_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    db.refresh(record)

    try:
        await redis_client.redis.set(f"webscan_cancel:{record.scan_id}", "1", ex=86400)
    except Exception:
        logger.warning("Could not set cancel signal for web scan %s", record.scan_id, exc_info=True)

    if record.acunetix_scan_id:
        try:
            with AcunetixClient() as client:
                client.abort_scan(record.acunetix_scan_id)
        except AcunetixError:
            logger.warning("Could not abort Acunetix scan %s", record.acunetix_scan_id, exc_info=True)

    try:
        await ws_manager.send(user.org_id, {
            "event": "webscan_cancelled",
            "scan_id": str(record.scan_id),
            "target_url": record.target_url,
            "status": record.status,
        })
    except Exception:
        logger.debug("Could not broadcast webscan_cancelled", exc_info=True)

    return _to_detail(record)


@router.get("/diagnostics")
async def webscan_diagnostics(user: User = Depends(require_webscan_owner)):
    """Check the Acunetix connection without starting a scan.

    Confirms the configured URL/key work and reports the available scanning
    profiles, so a misconfiguration can be spotted before a scan fails. The API
    key itself is never returned — only whether it is set.
    """
    result: dict = {
        "base_url": resolve_base_url(),
        "api_key_configured": bool((os.getenv("ACUNETIX_API_KEY") or "").strip()),
        "reachable": False,
        "profiles": [],
        "profile_id": "",
        "profile_name": "",
        "error": "",
    }

    if not result["base_url"]:
        result["error"] = (
            "ACUNETIX_URL is not set. Point it at your Acunetix console, "
            "e.g. https://acunetix.example.com:3443"
        )
        return result

    try:
        with AcunetixClient() as client:
            profiles = client.list_profiles()
            result["reachable"] = True
            result["profiles"] = [
                {"profile_id": str(p.get("profile_id") or ""), "name": str(p.get("name") or "")}
                for p in profiles
            ]
            try:
                resolved = client.resolve_profile_id()
                result["profile_id"] = resolved
                result["profile_name"] = next(
                    (p["name"] for p in result["profiles"] if p["profile_id"] == resolved),
                    "",
                )
            except AcunetixError as exc:
                result["error"] = str(exc)
    except AcunetixError as exc:
        result["error"] = str(exc)
    except Exception as exc:  # network/DNS failures surface as a readable message
        logger.warning("Acunetix diagnostics failed", exc_info=True)
        result["error"] = f"Could not reach Acunetix: {exc}"

    return result
