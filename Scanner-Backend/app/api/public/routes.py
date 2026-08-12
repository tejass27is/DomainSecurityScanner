import os
import time
import urllib.parse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import (
    ScanSummary,
    Organization,
    User,
    ActiveScan,
    PortFixRequest,
    HeaderFixRequest,
    TlsFixRequest,
    ResolvedFinding,
)
from app.api.analyzer.scoring_service import format_scoring_response, calculate_weighted_score, get_criticality_from_domain_keywords
from app.api.scanner.service import _validate_domain_dns
from app.api.auth.service import hashPassword
from app.api.admin.service import create_public_report_request
from app.core.redis_queue import RedisClient
from app.utils.email import send_scan_report_email
from app.utils.generate_scan_report_pdf import generate_domain_scan_report_pdf_bytes

router = APIRouter(prefix="/public", tags=["public"])
redis_client = RedisClient()

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Per-IP cache so repeated report downloads don't hammer the AbuseIPDB rate
# limit (free tier: 1000 req/day). A 24h TTL is a good balance — reputation
# doesn't change minute to minute.
_IP_REP_CACHE: dict = {}
_IP_REP_CACHE_TTL = 24 * 3600


def _enrich_ip_reputation(ips: list | None) -> list:
    """Turn stored IP strings into AbuseIPDB reputation dicts.

    The scan pipeline stores plain IP strings in scan_summary.ips, but the
    report/PDF expects dicts with abuseConfidenceScore / totalReports etc.
    Query AbuseIPDB for each unique IP, skip failures, and cache per IP.
    """
    if not ips:
        return []

    # Already-enriched dicts (future-proof) — return as-is.
    if all(isinstance(item, dict) for item in ips):
        return [item for item in ips if isinstance(item, dict)]

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return []

    enriched = []
    now = time.time()
    for ip in dict.fromkeys(str(item).strip() for item in ips if item):
        cached = _IP_REP_CACHE.get(ip)
        if cached and (now - cached[0]) < _IP_REP_CACHE_TTL:
            enriched.append(cached[1])
            continue
        try:
            response = httpx.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=8,
            )
            if response.status_code != 200:
                continue
            result = response.json().get("data", {})
            rep = {
                "ip": result.get("ipAddress") or ip,
                "abuseConfidenceScore": result.get("abuseConfidenceScore", 0),
                "totalReports": result.get("totalReports", 0),
                "countryCode": result.get("countryCode", ""),
                "isp": result.get("isp", ""),
                "domain": result.get("domain", ""),
                "isPublic": result.get("isPublic", True),
                "usageType": result.get("usageType", ""),
                "lastReportedAt": result.get("lastReportedAt"),
            }
            _IP_REP_CACHE[ip] = (now, rep)
            enriched.append(rep)
        except Exception:
            # One bad IP shouldn't break the whole report.
            continue
    return enriched


def _score_grade(score: int) -> str:
    """Grade label matching the public frontend overview thresholds."""
    if score >= 80:
        return "Optimal"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Moderate"
    return "Needs help"


def _build_report_data(row: ScanSummary):
    """Build the shared (categories, ip_reps, score, grade_label) used by the PDF report."""
    categories = []
    categories_payload = {}
    if row.app_security:
        categories.append({"name": "Application Security", "findings": _normalize_findings(row.app_security)})
        categories_payload["Application Security"] = row.app_security
    if row.network_security:
        categories.append({"name": "Network Security", "findings": _normalize_findings(row.network_security)})
        categories_payload["Network Security"] = row.network_security
    if row.tls_security:
        categories.append({"name": "TLS Security", "findings": _normalize_findings(row.tls_security)})
        categories_payload["TLS Security"] = row.tls_security
    if row.dns_security:
        categories.append({"name": "DNS Security", "findings": _normalize_findings(row.dns_security)})
        categories_payload["DNS Security"] = row.dns_security
    # NOTE: Mail Security findings live under DNS Security (stored by
    # evaluate_dns_security in the analyzer), NOT in row.mail_security which
    # is raw config. Adding a separate Mail Security category here would always
    # show "No findings." — misleading. The mail findings are correctly surfaced
    # under the DNS Security category below.
    # Enrich stored IP strings with live AbuseIPDB data so the PDF report's
    # "IP Reputation" section actually shows something (the scan pipeline
    # stores plain IP strings, not reputation dicts).
    ip_reps = _enrich_ip_reputation(row.ips)

    # IP Reputation always appears (mirrors the logged-in report), even when empty
    categories.append({"name": "IP Reputation", "isIpRep": True, "findings": ip_reps})

    # Use the stored scan score (the same number shown on the scan dashboard)
    # so the PDF always matches what the user saw in the app. Only fall back
    # to a fresh weighted calculation if the stored score is missing.
    if row.domain_score is not None:
        score = int(row.domain_score)
    else:
        criticality = row.domain_criticality or get_criticality_from_domain_keywords(row.domain)
        breakdown = calculate_weighted_score(categories_payload, criticality)
        score = int(round(float(breakdown.total_score), 2))
    return categories, ip_reps, score, _score_grade(score)

PUBLIC_USER_EMAIL = "public@shieldstat.local"
PUBLIC_USER_ID = "00000000-0000-0000-0000-000000000001"
PUBLIC_ORG_ID = "00000000-0000-0000-0000-000000000010"
PUBLIC_USER_PASSWORD = "PublicScan123!"


@router.get("/test-redis/{domain}")
async def test_redis(domain: str):
    """Test endpoint to verify Redis operations and progress values."""
    normalized_domain = domain.strip().lower()
    progress_key = f"scan_progress:{PUBLIC_ORG_ID}:{normalized_domain}"
    
    test_results = {}
    
    try:
        test_results["redis_connection"] = "ok"
        # Try to set a test value
        await redis_client.redis.set("test_key", "test_value", ex=60)
        test_results["set_operation"] = "ok"
        
        # Try to get it back
        test_val = await redis_client.redis.get("test_key")
        test_results["get_operation"] = f"ok (value={test_val})"
        
        # Check the actual progress key
        progress_val = await redis_client.redis.get(progress_key)
        test_results["progress_key"] = progress_key
        test_results["progress_value"] = str(progress_val) if progress_val else "not_set"
        
    except Exception as e:
        test_results["error"] = str(e)
    
    return test_results


def _clear_existing_public_scan_results(db: Session, domain: str) -> None:
    normalized_domain = domain.strip().lower()
    if not normalized_domain:
        return

    try:
        # Delete child rows that FK-reference scan_summary.domain FIRST.
        # Otherwise the DELETE below violates the FK constraint on Postgres
        # and the old summary survives — scan-status then reports "complete"
        # with the previous score while the new scan is still running.
        for model in (PortFixRequest, HeaderFixRequest, TlsFixRequest, ResolvedFinding):
            db.query(model).filter(model.domain == normalized_domain).delete(synchronize_session=False)

        db.query(ScanSummary).filter(ScanSummary.domain == normalized_domain).delete(synchronize_session=False)
        db.query(ActiveScan).filter(
            ActiveScan.domain == normalized_domain,
            ActiveScan.org_id == PUBLIC_ORG_ID,
        ).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _normalize_findings(payload: dict | None):
    if not payload:
        return []

    findings = []
    for rule_name, hosts in (payload or {}).items():
        if not isinstance(hosts, list):
            continue
        normalized_hosts = []
        severities = []
        for host in hosts:
            if isinstance(host, dict):
                host_severity = str(host.get("severity") or "").lower()
                if host_severity:
                    severities.append(host_severity)
                normalized_hosts.append({
                    "subdomain": host.get("subdomain") or host.get("host") or host.get("name"),
                    "ip": host.get("ip") or host.get("ip_address"),
                    "port": host.get("port"),
                    "severity": host.get("severity"),
                })
        # Dominant severity = the WORST one present among the hosts, matching
        # the scan dashboard (which labels a rule "high" if any host is high).
        # Using the last host's severity instead made rules with mixed-severity
        # hosts (e.g. a HIGH host followed by a LOW host) collapse to LOW and
        # wrongly disappear from the PDF report.
        severity = min(severities, key=lambda s: _SEVERITY_RANK.get(s, 99)) if severities else "info"
        findings.append({
            "rule": rule_name,
            "severity": severity,
            "hosts": normalized_hosts,
        })
    return findings


class PublicScanRequest(BaseModel):
    domain: str


class PublicReportEmailRequest(BaseModel):
    domain: str
    email: str
    first_name: str
    last_name: str


def ensure_public_org_exists(db: Session) -> None:
    public_user = db.query(User).filter(User.user_id == PUBLIC_USER_ID).first()
    if not public_user:
        public_user = db.query(User).filter(User.email == PUBLIC_USER_EMAIL).first()

    if not public_user:
        public_user = User(
            user_id=PUBLIC_USER_ID,
            email=PUBLIC_USER_EMAIL,
            password=hashPassword(PUBLIC_USER_PASSWORD),
            role="owner",
            org_id=None,
            email_verified=True,
        )
        db.add(public_user)
        db.flush()

    public_org = db.query(Organization).filter(Organization.org_id == PUBLIC_ORG_ID).first()
    if not public_org:
        public_org = Organization(
            org_id=PUBLIC_ORG_ID,
            user_id=public_user.user_id,
            domain=[],
        )
        db.add(public_org)
        db.flush()
        public_user.org_id = public_org.org_id

    if public_user.org_id != PUBLIC_ORG_ID:
        public_user.org_id = PUBLIC_ORG_ID

    db.commit()


@router.post("/scan")
async def public_scan(
    request: PublicScanRequest,
    db: Session = Depends(get_db),
):
    domain = request.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    is_valid, dns_message = _validate_domain_dns(domain)
    if not is_valid:
        raise HTTPException(status_code=422, detail=dns_message)

    ensure_public_org_exists(db)
    _clear_existing_public_scan_results(db, domain)

    scan_job = {"scan_id": PUBLIC_ORG_ID, "target": domain}
    print(f"[PUBLIC SCAN] Queueing job: {scan_job}")
    try:
        await redis_client.PushToQueue(data=scan_job)
    except Exception as e:
        print(f"[PUBLIC SCAN] ✗ Failed to queue scan job: {e}")
        print(f"[PUBLIC SCAN] Redis host: {redis_client.host}")
        raise HTTPException(status_code=503, detail="Unable to queue public scan. Redis is unavailable.")

    progress_key = f"scan_progress:{PUBLIC_ORG_ID}:{domain.strip().lower()}"
    try:
        payload = _build_progress_payload(10, status="queued", stage="queued", message="Scan queued")
        result = await redis_client.redis.set(progress_key, payload, ex=3600)
        print(f"[PUBLIC SCAN] ✓ Set progress key {progress_key} = {payload} (result={result})")
    except Exception as e:
        print(f"[PUBLIC SCAN] ✗ Failed to set progress: {e}")
        print(f"[PUBLIC SCAN] Redis host: {redis_client.host}")

    try:
        active_scan = db.query(ActiveScan).filter(
            ActiveScan.domain == domain,
            ActiveScan.org_id == PUBLIC_ORG_ID,
        ).first()

        if active_scan:
            active_scan.status = "pending"
        else:
            active_scan = ActiveScan(
                domain=domain,
                org_id=PUBLIC_ORG_ID,
                status="pending",
            )
            db.add(active_scan)

        db.commit()
        print(f"[PUBLIC SCAN] ✓ Created/updated ActiveScan for {domain}")
    except Exception as e:
        print(f"[PUBLIC SCAN] ✗ Failed to create ActiveScan: {e}")
        db.rollback()

    return {"message": "Public scan queued successfully", "domain": domain}


@router.get("/scan-status")
async def public_scan_status(
    domain: str = Query(..., description="Domain to check scan status"),
    db: Session = Depends(get_db),
):
    normalized_domain = domain.strip().lower()
    if not normalized_domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    summary = db.query(ScanSummary).filter(ScanSummary.domain == normalized_domain).first()
    if summary:
        return {
            "status": "complete",
            "progress": 100,
            "message": "Scan complete",
        }

    progress_key = f"scan_progress:{PUBLIC_ORG_ID}:{normalized_domain}"
    try:
        cached = await redis_client.redis.get(progress_key)
        print(f"[SCAN STATUS] key={progress_key}, raw_cached={repr(cached)}, type={type(cached).__name__}")
        status_payload = _parse_progress_payload(cached)
        if status_payload:
            print(f"[SCAN STATUS] ✓ Parsed progress payload: {status_payload}")
            return {
                "status": status_payload.get("status", "pending"),
                "progress": status_payload.get("progress", 0),
                "stage": status_payload.get("stage", "queued"),
                "message": status_payload.get("message", "Scan in progress"),
            }
        print(f"[SCAN STATUS] cached is None or invalid; continuing to fallback")
    except Exception as e:
        print(f"[SCAN STATUS] ✗ Redis get failed for {progress_key}: {e}")
        print(f"[SCAN STATUS] Redis host: {redis_client.host}")

    try:
        active_scan = db.query(ActiveScan).filter(
            ActiveScan.domain == normalized_domain,
            ActiveScan.org_id == PUBLIC_ORG_ID,
        ).first()
    except Exception as e:
        print(f"[SCAN STATUS] ✗ ActiveScan query failed: {e}")
        active_scan = None

    if active_scan:
        status_payload = _build_fallback_public_status(active_scan)
        return {
            "status": status_payload.get("status", active_scan.status or "pending"),
            "progress": status_payload.get("progress", 10),
            "stage": status_payload.get("stage", "queued"),
            "message": status_payload.get("message", "Scan in progress"),
        }

    return {
        "status": "not_started",
        "progress": 0,
        "message": "Scan has not started",
    }


# Public query for a lightweight domain overview
@router.post("/send-report")
def send_report_email(
    request: PublicReportEmailRequest,
    db: Session = Depends(get_db),
):
    domain = request.domain.strip().lower()
    email = request.email.strip().lower()
    first_name = request.first_name.strip()
    last_name = request.last_name.strip()

    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    if not first_name:
        raise HTTPException(status_code=400, detail="First name is required")
    if not last_name:
        raise HTTPException(status_code=400, detail="Last name is required")

    row = db.query(ScanSummary).filter(ScanSummary.domain == domain).first()
    if not row:
        raise HTTPException(status_code=404, detail="No scan report available for this domain")

    categories, ip_reps, score, grade_label = _build_report_data(row)

    report_payload = {
        "domain": domain,
        "score": score,
        "grade_label": grade_label,
        "categories": categories,
        "ip_reps": ip_reps,
    }

    pdf_bytes = generate_domain_scan_report_pdf_bytes(
        domain=domain,
        score=score,
        grade_label=grade_label,
        categories=categories,
        ip_reps=ip_reps,
    )

    send_scan_report_email(email, domain, pdf_bytes)
    create_public_report_request(
        db,
        email=email,
        domain=domain,
        first_name=first_name,
        last_name=last_name,
        report_payload=report_payload,
    )
    return {"message": "Report sent successfully", "email": email, "domain": domain}


@router.get("/download-report")
def download_report(
    domain: str = Query(..., description="Domain to download the report for"),
    db: Session = Depends(get_db),
):
    normalized_domain = domain.strip().lower()
    if not normalized_domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    row = db.query(ScanSummary).filter(ScanSummary.domain == normalized_domain).first()
    if not row:
        raise HTTPException(status_code=404, detail="No scan report available for this domain")

    categories, ip_reps, score, grade_label = _build_report_data(row)
    pdf_bytes = generate_domain_scan_report_pdf_bytes(
        domain=normalized_domain,
        score=score,
        grade_label=grade_label,
        categories=categories,
        ip_reps=ip_reps,
    )

    filename = f"{normalized_domain}-scan-report.pdf"
    quoted = urllib.parse.quote(filename)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"; filename*=UTF-8\'\'{quoted}'
        },
    )


@router.get("/domain-overview")
def public_domain_overview(
    domain: str = Query(..., description="Domain to preview"),
    db: Session = Depends(get_db),
):
    normalized_domain = domain.strip().lower()
    if not normalized_domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    row = db.query(ScanSummary).filter(ScanSummary.domain == normalized_domain).first()
    if not row:
        raise HTTPException(status_code=404, detail="No overview available for this domain")

    categories = {}
    if row.app_security:
        categories["Application Security"] = row.app_security
    if row.network_security:
        categories["Network Security"] = row.network_security
    if row.tls_security:
        categories["TLS Security"] = row.tls_security
    if row.dns_security:
        categories["DNS Security"] = row.dns_security
    if row.mail_security:
        categories["Mail Security"] = row.mail_security

    criticality = row.domain_criticality or get_criticality_from_domain_keywords(row.domain)
    breakdown = calculate_weighted_score(categories, criticality)
    scoring_response = format_scoring_response(breakdown)
    # Helper: mask IPs (hide last octet for IPv4, last group for IPv6)
    def _mask_ip(ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            if "." in ip:
                parts = ip.split(".")
                if len(parts) == 4:
                    return ".".join(parts[:3] + ["xxx"])
            if ":" in ip:
                parts = ip.split(":")
                return ":".join(parts[:3] + ["xxxx"])
        except Exception:
            return None
        return None

    # Sanitize category detail: remove ports and mask IPs. Keep subdomain + severity + short message.
    def _sanitize_category_items(items: dict) -> list:
        out = []
        # items expected as {check_name: [entries...]}
        for check_name, entries in items.items():
            for e in entries:
                sanitized = {
                    "check": check_name,
                    "subdomain": e.get("subdomain"),
                    "severity": e.get("severity"),
                }
                ip = e.get("ip") or e.get("ip_address")
                if ip:
                    sanitized["ip"] = _mask_ip(ip)
                # intentionally DO NOT include port information or raw details
                out.append(sanitized)
        return out

    def _build_category_preview(category_name: str) -> dict | None:
        if category_name not in categories:
            return None

        sanitized = _sanitize_category_items(categories[category_name])
        if not sanitized:
            return None

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_items = sorted(
            sanitized,
            key=lambda item: severity_order.get((item.get("severity") or "").lower(), 99)
        )

        return {
            "category": category_name,
            "top_findings": sorted_items[:3],
            "note": f"Top {category_name} findings are limited in the public preview.",
        }

    # Choose the single category to show in-detail (highest risk by weighted score)
    highest_risk_category = None
    try:
        highest_risk_category = max(
            scoring_response["scoring_breakdown"]["categories"],
            key=lambda c: c.get("weighted_score", 0)
        )["name"]
    except Exception:
        highest_risk_category = None

    detailed_preview = None
    if highest_risk_category and highest_risk_category in categories:
        # build sanitized list for this category and limit to top 5
        sanitized = _sanitize_category_items(categories[highest_risk_category])
        detailed_preview = {
            "category": highest_risk_category,
            "top_findings": sanitized[:5],
            "note": "Some details are redacted in the public preview. Sign up for the full report.",
        }

    other_summaries = []
    for c in scoring_response["scoring_breakdown"]["categories"]:
        name = c.get("name")
        if name == highest_risk_category:
            continue
        other_summaries.append({
            "category": name,
            "vulnerabilities": c.get("vulnerabilities", {}),
            "weighted_score": c.get("weighted_score", 0),
        })

    category_previews = []
    for name in ["Application Security", "Network Security"]:
        preview = _build_category_preview(name)
        if preview:
            category_previews.append(preview)

    # Headline score: prefer the stored scan score (matches the scan dashboard
    # and the PDF report) so every surface shows the same number.
    headline_score = row.domain_score if row.domain_score is not None else breakdown.total_score

    response = {
        "domain": row.domain,
        "summary": {
            "total_score": headline_score,
            "severity": row.severity,
            "category_count": len(categories),
            "highest_risk_category": highest_risk_category,
        },
        "preview": {
            "quick_findings": [
                {"title": "Scan available", "value": "Expanded public preview (redacted)"},
                {"title": "Requires login", "value": "Full report & download"},
            ],
            "detailed_preview": detailed_preview,
            "category_previews": category_previews,
            "other_categories_summary": other_summaries,
            "suggested_actions": [
                "Review this summary",
                "Sign up for full report",
                "Download detailed PDF after login",
            ],
        },
        "scoring_breakdown": scoring_response["scoring_breakdown"],
        "compliance": scoring_response["compliance"],
        "categories": categories,
        "full_report_required": True,
    }

    return response
