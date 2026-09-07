from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import dns.resolver
import dns.exception
from app.core.redis_queue import RedisClient
from app.db.models import Organization, ActiveScan

redis_client = RedisClient()


def _normalize_domain_for_match(domain: str) -> str:
    """Normalize a domain for ownership comparison.

    Mirrors how registration normalizes before storing (lowercase, no scheme,
    no www., no trailing dot), so scanning "www.example.com" works when the
    account holds "example.com" and vice versa.
    """
    return (
        (domain or "")
        .strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .strip("/")
        .rstrip(".")
        .lstrip("www.")
    )


def _build_cancel_signal_keys(org_id: str, domain: str) -> list[str]:
    domain = (domain or "").strip().lower()
    org_id = (org_id or "").strip()
    if not org_id or not domain:
        return []

    scan_id = f"{org_id}:{domain}"
    return [
        f"scan_cancel:{org_id}:{domain}",
        f"scan_cancel:{scan_id}:{domain}",
    ]


def _validate_domain_dns(domain: str) -> tuple[bool, str]:
    """
    Resolves the domain's A records via DNS.
    Returns (is_valid, message) so the caller can build a uniform response.
    """
    try:
        dns.resolver.resolve(domain, "A")
        return True, "Domain is valid and reachable."
    except dns.resolver.NXDOMAIN:
        return False, f"Domain '{domain}' does not exist. Please check the domain name and try again."
    except dns.resolver.NoAnswer:
        return False, f"Domain '{domain}' has no DNS A records configured. Ensure the domain is set up correctly."
    except dns.exception.Timeout:
        return False, f"DNS lookup for '{domain}' timed out. The domain may be temporarily unreachable."
    except dns.resolver.NoNameservers:
        return False, f"No nameservers could be reached for '{domain}'. The domain may be invalid or DNS is unavailable."
    except Exception:
        return False, f"Could not resolve '{domain}'. Verify the domain name is correct."


async def create_scan_task_to_queue(db: Session, domain: str, org_id: str, schedule_id: str | None = None):
    try:
        domain = domain.strip().lower()
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")

        is_valid, dns_message = _validate_domain_dns(domain)
        if not is_valid:
            return JSONResponse(
                status_code=422,
                content={"detail": dns_message, "domain_validation": False}
            )

        org = db.query(Organization).filter(Organization.org_id == org_id).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        # 🔐 Verify domain ownership: user can only scan domains they've registered.
        # org.domain is a JSON array, but guard against a stray string value the
        # same way the VAPT module does, and normalize both sides so case / www /
        # scheme variants of the same registered domain never false-403.
        raw_org_domains = org.domain or []
        if not isinstance(raw_org_domains, list):
            raw_org_domains = [raw_org_domains]
        org_domains = {
            _normalize_domain_for_match(str(d))
            for d in raw_org_domains
            if str(d).strip()
        }
        if _normalize_domain_for_match(domain) not in org_domains:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"🔴 SECURITY: Unauthorized scan attempt for domain '{domain}' by org '{org_id}'")
            raise HTTPException(
                status_code=403,
                detail=f"Domain '{domain}' is not registered to this account. Please add the domain to your account before scanning."
            )

        db.commit()

        scan_job = {
            "scan_id": f"{org_id}:{domain}",
            "org_id": org_id,
            "domain": domain,
            "target": domain,
        }
        if schedule_id:
            scan_job["schedule_id"] = str(schedule_id)

        queue_status = "queued"
        warning_message = None
        try:
            await redis_client.PushToQueue(data=scan_job)
        except Exception as queue_error:
            queue_status = "deferred"
            warning_message = f"Queue submission failed: {queue_error}"

        try:
            active_scan = db.query(ActiveScan).filter(
                ActiveScan.domain == domain,
                ActiveScan.org_id == org_id,
            ).first()
            if active_scan:
                active_scan.org_id = org_id
                active_scan.status = "pending"
            else:
                active_scan = ActiveScan(
                    domain=domain,
                    org_id=org_id,
                    status="pending",
                )
                db.add(active_scan)
            db.commit()
        except Exception:
            db.rollback()

        response = {
            "message": "Scan task registered successfully",
            "domain_validation": True,
            "queue_status": queue_status,
        }
        if queue_status == "deferred" and warning_message:
            response["warning"] = warning_message
        return response
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise e


def cancel_active_scans_for_org(db: Session, org_id: str):
    """Immediately stop all active scans for an org so logout clears running scans."""
    if not org_id:
        return []

    cancelled_domains = []
    try:
        active_scans = db.query(ActiveScan).filter(ActiveScan.org_id == org_id).all()
        for active_scan in active_scans or []:
            domain = (getattr(active_scan, "domain", None) or "").strip().lower()
            if not domain:
                continue
            active_scan.status = "cancelled"
            cancelled_domains.append(domain)
            try:
                for key in _build_cancel_signal_keys(org_id, domain):
                    redis_client.redis.set(key, "1", ex=1800)
                redis_client.redis.delete(f"scan_progress:{org_id}:{domain}")
            except Exception:
                pass
        db.commit()
        return cancelled_domains
    except Exception:
        db.rollback()
        return []
