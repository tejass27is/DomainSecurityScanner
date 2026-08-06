import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import ScanSummary, Organization, User, ActiveScan
from app.api.analyzer.scoring_service import format_scoring_response, calculate_weighted_score, get_criticality_from_domain_keywords
from app.api.scanner.service import _validate_domain_dns
from app.api.auth.service import hashPassword
from app.api.admin.service import create_public_report_request
from app.core.redis_queue import RedisClient
from app.utils.email import send_scan_report_email
from app.utils.generate_scan_report_pdf import generate_domain_scan_report_pdf_bytes

router = APIRouter(prefix="/public", tags=["public"])
redis_client = RedisClient()


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
    if row.mail_security:
        categories.append({"name": "Mail Security", "findings": _normalize_findings(row.mail_security)})
        categories_payload["Mail Security"] = row.mail_security

    ip_reps = []
    if isinstance(row.ips, list):
        ip_reps = [item for item in row.ips if isinstance(item, dict)]

    # IP Reputation always appears (mirrors the logged-in report), even when empty
    categories.append({"name": "IP Reputation", "isIpRep": True, "findings": ip_reps})

    criticality = row.domain_criticality or get_criticality_from_domain_keywords(row.domain)
    breakdown = calculate_weighted_score(categories_payload, criticality)
    score = round(float(breakdown.total_score), 2)
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
        db.query(ScanSummary).filter(ScanSummary.domain == normalized_domain).delete(synchronize_session=False)
        db.query(ActiveScan).filter(
            ActiveScan.domain == normalized_domain,
            ActiveScan.org_id == PUBLIC_ORG_ID,
        ).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()


def _normalize_findings(payload: dict | None):
    if not payload:
        return []

    findings = []
    for rule_name, hosts in (payload or {}).items():
        if not isinstance(hosts, list):
            continue
        normalized_hosts = []
        severity = "info"
        for host in hosts:
            if isinstance(host, dict):
                normalized_hosts.append({
                    "subdomain": host.get("subdomain") or host.get("host") or host.get("name"),
                    "ip": host.get("ip") or host.get("ip_address"),
                    "port": host.get("port"),
                    "severity": host.get("severity"),
                })
                if host.get("severity"):
                    severity = str(host.get("severity")).lower()
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
        result = await redis_client.redis.set(progress_key, "0", ex=3600)
        print(f"[PUBLIC SCAN] ✓ Set progress key {progress_key} = 0 (result={result})")
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

    try:
        active_scan = db.query(ActiveScan).filter(
            ActiveScan.domain == normalized_domain,
            ActiveScan.org_id == PUBLIC_ORG_ID,
        ).first()
    except Exception:
        active_scan = None

    if active_scan:
        progress = 10
        progress_key = f"scan_progress:{PUBLIC_ORG_ID}:{normalized_domain}"
        try:
            cached = await redis_client.redis.get(progress_key)
            print(f"[SCAN STATUS] key={progress_key}, raw_cached={repr(cached)}, type={type(cached).__name__}")
            if cached is not None:
                try:
                    if isinstance(cached, bytes):
                        cached_str = cached.decode('utf-8', errors='ignore')
                    else:
                        cached_str = str(cached)
                    progress_int = int(cached_str)
                    progress = min(max(progress_int, 0), 100)
                    print(f"[SCAN STATUS] ✓ Parsed progress: {cached_str} -> {progress}")
                except (ValueError, TypeError) as ve:
                    print(f"[SCAN STATUS] ✗ Failed to parse '{cached}': {ve}")
                    progress = 10
            else:
                print(f"[SCAN STATUS] cached is None, using default progress=10")
        except Exception as e:
            print(f"[SCAN STATUS] ✗ Redis get failed for {progress_key}: {e}")
            print(f"[SCAN STATUS] Redis host: {redis_client.host}")
            progress = 10

        return {
            "status": active_scan.status or "pending",
            "progress": progress,
            "message": "Scan in progress",
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

    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

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
    create_public_report_request(db, email=email, domain=domain, report_payload=report_payload)
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

    response = {
        "domain": row.domain,
        "summary": {
            "total_score": breakdown.total_score,
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
