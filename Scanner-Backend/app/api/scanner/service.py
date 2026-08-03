from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import dns.resolver
import dns.exception
from app.core.redis_queue import RedisClient
from app.db.models import Organization, ActiveScan

redis_client = RedisClient()


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


async def create_scan_task_to_queue(db: Session, domain: str, org_id: str):
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

        org_domains = list(org.domain) if org.domain else []

        if domain not in org_domains:
            raise HTTPException(
                status_code=403,
                detail="Domain not registered. Please add the domain to your account before scanning."
            )

        db.commit()

        scan_job = {
            "scan_id": org_id,
            "target": domain
        }

        await redis_client.PushToQueue(data=scan_job)

        active_scan = db.query(ActiveScan).filter(
            ActiveScan.domain == domain,
            ActiveScan.org_id == org_id
        ).first()
        if active_scan:
            active_scan.org_id = org_id
            active_scan.status = "pending"
        else:
            active_scan = ActiveScan(
                domain=domain,
                org_id=org_id,
                status="pending"
            )
            db.add(active_scan)
        
        db.commit()

        return {
            "message": "Scan task registered successfully",
            "domain_validation": True
        }
    except Exception as e:
        db.rollback()
        raise e
