import json
import uuid
from datetime import datetime, timezone 
from sqlalchemy.orm import Session
from app.core.websocket_manager import ws_manager
from app.db.models import (
    ScanSummary,
    PortFixRequest,
    HeaderFixRequest,
    TlsFixRequest,
)
from app.core.redis_queue import redis_client
from collections import defaultdict
from app.api.analyzer.controller import get_cvss_severity
from fastapi import HTTPException

import ssl
import socket
import httpx

# ✅ FIXED FUNCTION #1 - Create fix request in database (with validation)
async def create_fix_request_in_db(
    db: Session,
    org_id: str,
    domain: str,
    host: str,
    port: int,
    user_id: str = None,
    service: str = None
):
    # ✅ Lookup by org_id — get the actual stored root domain
    scan_record = db.query(ScanSummary).filter(
        ScanSummary.org_id == org_id
    ).first()

    if not scan_record:
        raise HTTPException(
            status_code=400,
            detail=f"No scan found for this organization. Please run a scan first."
        )

    root_domain = scan_record.domain  # ✅ exact value stored in scan_summary

    scan_id = str(uuid.uuid4())

    fix_request = PortFixRequest(
        scan_id=scan_id,
        org_id=org_id,
        user_id=user_id,
        domain=root_domain,   # ✅ FK-safe, matches scan_summary exactly
        host=host,            # ✅ original subdomain preserved here
        port_number=port,
        service=service,
        fix_type="port",
        status="pending",
    )

    db.add(fix_request)
    db.commit()
    db.refresh(fix_request)

    return scan_id, fix_request

# ✅ FIXED FUNCTION #2 - Queue fix job with validation
async def queue_fix_job(
    org_id: str, 
    domain: str,
    fix_type: str, 
    data: dict,
    db: Session = None,
    user_id: str = None
):
    host = data.get("host")
    port = data.get("port")

    # ✅ No more string splitting — let DB tell us the root domain
    if not isinstance(port, int) or port <= 0 or port > 65535:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid port number: {port}. Must be between 1 and 65535."
        )

    if db:
        try:
            scan_id, fix_request = await create_fix_request_in_db(
                db=db,
                org_id=org_id,
                domain=domain,       # pass original, resolved inside
                host=host or domain,
                port=port,
                user_id=user_id,
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create fix request: {str(e)}"
            )
    else:
        scan_id = str(uuid.uuid4())
    
    # Queue the job
    job = {
        "scan_id": scan_id,
        "org_id": org_id,
        "domain": domain,
        "fix_type": fix_type,
        "data": {
            "host": host,
            "port": port,
        },
        "created_at": datetime.utcnow().isoformat()
    }

    await redis_client.rpush(
        "fix_queue",
        json.dumps(job)
    )

    return {
        "message": "Fix queued successfully",
        "scan_id": scan_id,
        "job": job
    }


# ✅ FIXED FUNCTION #3 - Apply fix result and update scan summary
def apply_fix_result(
    org_id: str, 
    domain: str, 
    fix_type: str, 
    result: dict, 
    db: Session,
    scan_id: str = None,
) -> dict:
    fail = {"success": False, "domain_score": None, "severity": None}

    # ✅ Update PortFixRequest status
    if scan_id:
        fix_record = db.query(PortFixRequest).filter(
            PortFixRequest.scan_id == scan_id
        ).first()
        if fix_record:
            is_closed = _is_fix_successful(result)
            fix_record.status = "completed"
            fix_record.is_open = not is_closed
            fix_record.verification_scan_time = datetime.utcnow()
            db.add(fix_record)
            db.commit()

    # ✅ Check if fix was successful before updating scan summary
    if not _is_fix_successful(result):
        return fail

    # ✅ Get the issue key and category for this fix type
    issue_key = FIX_TYPE_TO_ISSUE_KEY.get(fix_type)
    category = FIX_TYPE_TO_CATEGORY.get(fix_type)

    if not issue_key or not category:
        return fail

    # ✅ Get the scan summary
    # ✅ Get the scan summary
    summary = db.query(ScanSummary).filter(
        ScanSummary.org_id == org_id
    ).first()

    if not summary:
        return fail

    # ✅ Remove the fixed issue
    removed = _remove_fixed_issue(summary, issue_key, domain, category)
    if not removed:
        return fail

    # ✅ Recalculate the security score
    _recalculate_score(summary)

    # ✅ Save to database
    db.add(summary)
    db.commit()
    db.refresh(summary)

    return {
        "success": True,
        "domain_score": summary.domain_score,
        "severity": summary.severity,
    }


# ✅ Helper functions
def _is_fix_successful(result) -> bool:
    """Check if the fix result indicates success"""
    if isinstance(result, dict):
        # Direct boolean flags
        for key in ("success", "is_success", "fixed"):
            if key in result:
                return bool(result[key])

        # Check status field
        status = result.get("status")
        if isinstance(status, bool):
            return status

        status_str = str(status).strip().lower()
        if status_str:
            return status_str in {
                "success",
                "succeeded",
                "ok",
                "true",
                "closed",  # PORT CLOSED = FIXED
            }

    return False


def _remove_fixed_issue(
    summary: ScanSummary, 
    issue_key: str, 
    domain: str, 
    category: str
) -> bool:
    """Remove a fixed issue from the scan summary"""
    if category not in ALLOWED_CATEGORIES:
        return False

    category_data = dict(getattr(summary, category) or {})
    findings = list(category_data.get(issue_key, []))
    
    if not findings:
        return False
    import logging
    logging.getLogger(__name__).info(
        f"[remove_fixed_issue] looking for subdomain='{domain}' "
        f"in {len(findings)} findings under '{issue_key}'"
    )
    for f in findings:
        logging.getLogger(__name__).info(f"  stored: '{f.get('subdomain')}'")



    # Filter out the fixed finding
    updated = [f for f in findings if f.get("subdomain") != domain]
    
    if len(updated) == len(findings):
        # Nothing was removed
        return False

    # Update or remove the issue
    if updated:
        category_data[issue_key] = updated
    else:
        category_data.pop(issue_key, None)

    setattr(summary, category, category_data or None)
    return True


def _recalculate_score(summary: ScanSummary):
    """Recalculate the domain security score"""
    subdomain_penalty: dict[str, int] = defaultdict(int)

    category_blocks = [
        summary.app_security or {},
        summary.network_security or {},
        summary.tls_security or {},
        summary.dns_security or {},
    ]

    # Calculate penalties for remaining issues
    for block in category_blocks:
        for issue_key, findings in block.items():
            penalty = ISSUE_KEY_TO_PENALTY.get(issue_key, 0)
            if not penalty:
                continue
            for finding in findings or []:
                subdomain = finding.get("subdomain")
                if subdomain:
                    subdomain_penalty[subdomain] += penalty

    # Calculate new score
    subdomain_names = list(subdomain_penalty.keys())
    if not subdomain_names:
        summary.domain_score = 100
        summary.severity = "low"
        return

    scores = [
        max(100 - subdomain_penalty.get(name, 0), 0) 
        for name in subdomain_names
    ]
    domain_score = int(sum(scores) / len(scores))

    summary.domain_score = domain_score
    summary.severity = get_cvss_severity(domain_score)["severity"]


# Maps
FIX_TYPE_TO_ISSUE_KEY = {
    # Network Security
    "unexpected_port": "Unexpected open port",
    "risky_port": "Risky port exposed",
    "port": "Unexpected open port",  # ✅ Added for "port" fix type
    # Application Security
    "missing_csp": "Missing CSP header",
    "missing_hsts": "Missing HSTS header",
    "missing_x_frame": "Missing X-Frame-Options",
    "missing_x_content": "Missing X-Content-Type-Options",
    "http_without_https": "HTTP without HTTPS",
    # TLS Security
    "expired_tls": "Expired TLS",
    "weak_tls": "Weak TLS version",
    "tls_missing_443": "443 open without TLS",
    # DNS Security
    "missing_ns": "Missing NS record",
    "missing_mx": "Missing MX record",
    "missing_txt": "Missing TXT record",
    "duplicate_spf": "Duplicate SPF record",
    "weak_spf": "Weak SPF policy",
    "missing_spf": "Missing SPF record",
    "missing_dmarc": "Missing DMARC",
    "weak_dmarc": "Weak DMARC policy",
    "missing_dkim": "Missing DKIM",
}

FIX_TYPE_TO_CATEGORY = {
    # Network Security
    "unexpected_port": "network_security",
    "risky_port": "network_security",
    "port": "network_security",  # ✅ Added for "port" fix type
    # Application Security
    "missing_csp": "app_security",
    "missing_hsts": "app_security",
    "missing_x_frame": "app_security",
    "missing_x_content": "app_security",
    "http_without_https": "app_security",
    # TLS Security
    "expired_tls": "tls_security",
    "weak_tls": "tls_security",
    "tls_missing_443": "tls_security",
    # DNS Security
    "missing_ns": "dns_security",
    "missing_mx": "dns_security",
    "missing_txt": "dns_security",
    "duplicate_spf": "dns_security",
    "weak_spf": "dns_security",
    "missing_spf": "dns_security",
    "missing_dmarc": "dns_security",
    "weak_dmarc": "dns_security",
    "missing_dkim": "dns_security",
}

ISSUE_KEY_TO_PENALTY = {
    # DNS
    "Missing NS record": 2,
    "Missing MX record": 2,
    "Missing TXT record": 1,
    # Application
    "HTTP without HTTPS": 20,
    "Missing CSP header": 3,
    "Missing HSTS header": 4,
    "Missing X-Frame-Options": 2,
    "Missing X-Content-Type-Options": 2,
    # Network
    "Risky port exposed": 10,
    "Unexpected open port": 8,
    # TLS
    "443 open without TLS": 20,
    "Expired TLS": 20,
    "Weak TLS version": 15,
}

ALLOWED_CATEGORIES = {
    "app_security", 
    "network_security", 
    "tls_security", 
    "dns_security"
}




# ── Header name map ───────────────────────────────────────────────────────────

HEADER_FIX_TYPE_TO_HEADER_NAME: dict[str, str] = {
    "missing_csp":       "content-security-policy",
    "missing_hsts":      "strict-transport-security",
    "missing_x_frame":   "x-frame-options",
    "missing_x_content": "x-content-type-options",
}


# ── Helper: probe HTTP headers ────────────────────────────────────────────────

async def _fetch_headers(subdomain: str) -> dict[str, str]:
    """
    Return response headers (lowercased keys) for the given subdomain.
    Tries HTTPS first, falls back to HTTP.
    Raises httpx.HTTPError on complete failure.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10,
                verify=False,           # cert validity checked separately in TLS path
            ) as client:
                resp = await client.get(url)
                return {k.lower(): v for k, v in resp.headers.items()}
        except httpx.ConnectError:
            continue
    raise httpx.ConnectError(f"Could not reach {subdomain} over HTTPS or HTTP")


# ── Helper: probe TLS ─────────────────────────────────────────────────────────

def _check_tls(subdomain: str, fix_type: str) -> bool:
    """
    Returns True if the TLS issue identified by fix_type is now resolved.

    fix_type semantics:
        expired_tls     → cert expiry date is in the future
        weak_tls        → negotiated protocol is TLSv1.2 or TLSv1.3
        tls_missing_443 → port 443 is open and a valid TLS handshake succeeds
    """
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((subdomain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=subdomain) as ssock:
                protocol = ssock.version()          # e.g. "TLSv1.3"
                cert = ssock.getpeercert()

                if fix_type == "tls_missing_443":
                    return True                     # handshake succeeded → port open + TLS present

                if fix_type == "expired_tls":
                    not_after_str = cert.get("notAfter", "")
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    return not_after.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)

                if fix_type == "weak_tls":
                    return protocol in ("TLSv1.2", "TLSv1.3")

    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        return False

    return False


# ── Public: verify header fix ─────────────────────────────────────────────────

async def verify_header_fix(
    org_id: str,
    domain: str,
    subdomain: str,
    fix_type: str,
    db,
    user_id: str = None,
) -> dict:
    """
    1. Validates the fix_type.
    2. Probes the subdomain for the expected header.
    3. Persists a HeaderFixRequest record.
    4. If header is present → calls apply_fix_result() to update scan_summary score.
    5. Returns a result dict consumed directly by the route.
    """
    header_name = HEADER_FIX_TYPE_TO_HEADER_NAME.get(fix_type)
    if not header_name:
        raise ValueError(f"Unknown header fix_type: {fix_type!r}")

    # ── Resolve root domain from DB (same pattern as port fix) ───────────────
    from app.db.models import ScanSummary
    from fastapi import HTTPException

    scan_record = db.query(ScanSummary).filter(ScanSummary.org_id == org_id).first()
    if not scan_record:
        raise HTTPException(
            status_code=400,
            detail="No scan found for this organization. Please run a scan first.",
        )
    root_domain = scan_record.domain

    # ── Probe headers ─────────────────────────────────────────────────────────
    scan_id = str(uuid.uuid4())
    header_present = False
    status = "failed"

    try:
        headers = await _fetch_headers(subdomain)
        header_present = header_name in headers
        status = "completed"
    except Exception:
        status = "failed"

    # ── Persist record ────────────────────────────────────────────────────────
    fix_record = HeaderFixRequest(
        scan_id=scan_id,
        org_id=org_id,
        user_id=user_id,
        domain=root_domain,
        fix_type=fix_type,
        status=status,
        header_present=header_present,
        verification_scan_time=datetime.now(timezone.utc),
    )
    db.add(fix_record)
    db.commit()

    # ── Update score if fixed ─────────────────────────────────────────────────
    score_update: dict = {}
    if header_present:
        score_update = apply_fix_result(
            org_id=org_id,
            domain=subdomain,
            fix_type=fix_type,
            result={"status": "closed"},        # reuse existing helper; "closed" → success
            db=db,
            scan_id=scan_id,
        )

    return {
        "ok": True,
        "scan_id": scan_id,
        "header_present": header_present,
        "status": status,
        "domain_score": score_update.get("domain_score"),
        "severity": score_update.get("severity"),
        "message": (
            f"Header '{header_name}' detected — fix confirmed. Score updated."
            if header_present
            else f"Header '{header_name}' still missing on {subdomain}."
        ),
    }


# ── Public: verify TLS fix ────────────────────────────────────────────────────

async def verify_tls_fix(
    org_id: str,
    domain: str,
    subdomain: str,
    fix_type: str,
    db,
    user_id: str = None,
) -> dict:
    """
    1. Validates the fix_type.
    2. Probes the subdomain TLS state.
    3. Persists a TlsFixRequest record.
    4. If resolved → calls apply_fix_result() to update scan_summary score.
    5. Returns a result dict consumed directly by the route.
    """
    from app.db.models import ScanSummary
    from fastapi import HTTPException

    VALID_TLS_FIX_TYPES = {"expired_tls", "weak_tls", "tls_missing_443"}
    if fix_type not in VALID_TLS_FIX_TYPES:
        raise ValueError(f"Unknown TLS fix_type: {fix_type!r}")

    # ── Resolve root domain ───────────────────────────────────────────────────
    scan_record = db.query(ScanSummary).filter(ScanSummary.org_id == org_id).first()
    if not scan_record:
        raise HTTPException(
            status_code=400,
            detail="No scan found for this organization. Please run a scan first.",
        )
    root_domain = scan_record.domain

    # ── Probe TLS ─────────────────────────────────────────────────────────────
    scan_id = str(uuid.uuid4())
    tls_ok = False
    status = "failed"

    try:
        tls_ok = _check_tls(subdomain, fix_type)
        status = "completed"
    except Exception:
        status = "failed"

    # ── Persist record ────────────────────────────────────────────────────────
    fix_record = TlsFixRequest(
        scan_id=scan_id,
        org_id=org_id,
        user_id=user_id,
        domain=root_domain,
        fix_type=fix_type,
        status=status,
        tls_ok=tls_ok,
        verification_scan_time=datetime.now(timezone.utc),
    )
    db.add(fix_record)
    db.commit()

    # ── Update score if fixed ─────────────────────────────────────────────────
    score_update: dict = {}
    if tls_ok:
        score_update = apply_fix_result(
            org_id=org_id,
            domain=subdomain,
            fix_type=fix_type,
            result={"status": "closed"},
            db=db,
            scan_id=scan_id,
        )

    return {
        "ok": True,
        "scan_id": scan_id,
        "tls_ok": tls_ok,
        "status": status,
        "domain_score": score_update.get("domain_score"),
        "severity": score_update.get("severity"),
        "message": (
            f"TLS issue '{fix_type}' resolved on {subdomain}. Score updated."
            if tls_ok
            else f"TLS issue '{fix_type}' still present on {subdomain}."
        ),
    }
