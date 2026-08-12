from datetime import timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.db.base import get_db
from app.db.models import ScanSummary, ScanScoreHistory, User
from app.core.middleware import protect
from app.api.analyzer.scoring_service import (
    calculate_weighted_score,
    format_scoring_response,
    get_criticality_from_domain_keywords,
)
import httpx
import os

router = APIRouter(prefix="/score", tags=["Scoring"])

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def build_categorized_vulnerabilities(scans: ScanSummary) -> dict:
    categorized = {}

    if scans.app_security:
        categorized["Application Security"] = scans.app_security
    if scans.network_security:
        categorized["Network Security"] = scans.network_security
    if scans.tls_security:
        categorized["TLS Security"] = scans.tls_security
    if scans.dns_security:
        categorized["DNS Security"] = scans.dns_security

    return categorized


@router.get("/get_score")
def get_score(
    domain: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    """
    Get domain security score with weighted scoring breakdown and compliance status.
    
    Returns:
        - total_score: Final weighted security score (0-100)
        - base_score: Score before criticality adjustment
        - scoring_breakdown: Detailed breakdown by category with weights
        - compliance: Compliance readiness for PCI-DSS, SOC2, GDPR, CIS
        - legacy fields: domain_score, severity for backward compatibility
    """
    normalized_domain = domain.strip().lower()

    row = db.execute(
        text(
            """
            SELECT
                domain,
                org_id,
                domain_score,
                weighted_score,
                severity,
                mail_security,
                app_security,
                network_security,
                tls_security,
                dns_security,
                ips
            FROM scan_summary
            WHERE domain = :domain
              AND (:org_id IS NULL OR org_id = :org_id OR org_id IS NULL)
            ORDER BY CASE
                WHEN org_id = :org_id THEN 0
                WHEN org_id IS NULL THEN 1
                ELSE 2
            END
            LIMIT 1
            """
        ),
        {"org_id": current_user.org_id, "domain": normalized_domain},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Score not found for the given domain.")

    score_data = {
        "domain": row.domain,
        "org_id": row.org_id,
        "domain_score": row.domain_score,
        "weighted_score": row.weighted_score,
        "domain_criticality": None,
        "severity": row.severity,
        "mail_security": row.mail_security,
        "app_security": row.app_security,
        "network_security": row.network_security,
        "tls_security": row.tls_security,
        "dns_security": row.dns_security,
        "ips": row.ips,
    }

    # Build categories dict for weighted scoring
    categories = {}
    if score_data["app_security"]:
        categories["Application Security"] = score_data["app_security"]
    if score_data["network_security"]:
        categories["Network Security"] = score_data["network_security"]
    if score_data["tls_security"]:
        categories["TLS Security"] = score_data["tls_security"]
    if score_data["dns_security"]:
        categories["DNS Security"] = score_data["dns_security"]
    if score_data["mail_security"]:
        categories["Mail Security"] = score_data["mail_security"]

    # Use stored criticality or auto-detect from domain
    criticality = score_data["domain_criticality"] or get_criticality_from_domain_keywords(score_data["domain"])

    # Calculate weighted score (for the breakdown panel / compliance)
    breakdown = calculate_weighted_score(categories, criticality)
    scoring_response = format_scoring_response(breakdown)

    # The stored domain_score IS the weighted total (merged at scan time in
    # calculate_and_store_summary). Use it for the headline fields so the
    # dashboard headline, PDF and this response can never drift apart.
    #
    # Legacy rows (scanned before the merge) have weighted_score = NULL — their
    # domain_score still holds the old worker average. Fall back to the freshly
    # computed weighted total for those so the headline always agrees with the
    # breakdown panel.
    merged_score = (
        score_data["domain_score"]
        if score_data.get("weighted_score") is not None and score_data["domain_score"] is not None
        else breakdown.total_score
    )

    # Extract IP reputation score if available
    ip_reputation_score = None
    if score_data["ips"] and isinstance(score_data["ips"], list) and len(score_data["ips"]) > 0:
        first_ip = score_data["ips"][0]
        if isinstance(first_ip, dict):
            ip_reputation_score = first_ip.get("abuseConfidenceScore")

    response = {
        # New weighted scoring fields — total_score == stored domain_score (merged)
        "total_score": merged_score,
        "base_score": breakdown.base_score,
        "weighted_score": merged_score,
        "scoring_breakdown": scoring_response["scoring_breakdown"],
        "compliance": scoring_response["compliance"],

        # Legacy fields for backward compatibility
        "org_id": score_data["org_id"],
        "domain_score": merged_score,
        "host": {
            "domain": score_data["domain"],
            "mail_security": score_data["mail_security"] or {}
        },
        "severity": score_data["severity"],
        "categorized_vulnerabilities": categories,
        "ips": score_data["ips"] or [],
        "domain_criticality": criticality,
    }

    return response


@router.delete("/delete_score/{org_id}")
def delete_score(
    org_id: str,
    db: Session = Depends(get_db)
):
    score = db.query(ScanSummary).filter(
        ScanSummary.org_id == org_id
    ).first()
    if not score:
        raise HTTPException(status_code=404, detail="Score not found")
    
    db.delete(score)
    db.commit()
    return {"detail": "Score deleted successfully"}


@router.put("/set-criticality")
def set_domain_criticality(
    domain: str,
    criticality: str = Query(..., description="critical|high|medium|low"),
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    """
    Set domain criticality level (admin only).
    This affects the final weighted score multiplier and compliance strictness.
    
    Levels:
    - critical: Financial, healthcare, government systems (1.5x multiplier)
    - high: E-commerce, payment processors (1.3x multiplier)
    - medium: Standard business systems (1.0x multiplier)
    - low: Informational, non-critical services (0.8x multiplier)
    """
    valid_levels = ["critical", "high", "medium", "low"]
    if criticality.lower() not in valid_levels:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid criticality. Must be one of: {', '.join(valid_levels)}"
        )
    
    score = db.query(ScanSummary).filter(
        ScanSummary.org_id == current_user.org_id,
        ScanSummary.domain == domain.strip().lower()
    ).first()
    
    if not score:
        raise HTTPException(status_code=404, detail="Domain scan not found")
    
    score.domain_criticality = criticality.lower()
    db.commit()
    
    return {
        "domain": score.domain,
        "criticality": score.domain_criticality,
        "message": f"Domain criticality updated to {criticality.lower()}"
    }


@router.get("/criticality-levels")
def get_criticality_levels():
    """Get available criticality levels with descriptions."""
    return {
        "levels": [
            {
                "id": "critical",
                "name": "Critical",
                "multiplier": 1.5,
                "description": "Processes sensitive data (finance, healthcare, government)",
                "examples": ["Banks", "Payment processors", "Healthcare portals", "Government systems"]
            },
            {
                "id": "high",
                "name": "High",
                "multiplier": 1.3,
                "description": "E-commerce and customer-facing systems",
                "examples": ["E-commerce sites", "Payment gateways", "SaaS platforms", "Customer portals"]
            },
            {
                "id": "medium",
                "name": "Medium",
                "multiplier": 1.0,
                "description": "Standard business systems",
                "examples": ["Corporate websites", "Internal tools", "Standard web applications"]
            },
            {
                "id": "low",
                "name": "Low",
                "multiplier": 0.8,
                "description": "Non-critical informational services",
                "examples": ["Blogs", "News sites", "Documentation", "Informational portals"]
            }
        ]
    }


@router.get("/ip-reputation")
async def ip_reputation(
    ip: str = Query(..., description="IP address to check"),
    current_user: User = Depends(protect),
):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="AbuseIPDB API key not configured")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"AbuseIPDB error: {response.text}",
                )
            result = response.json().get("data", {})
            return {
                "ip": ip,
                "abuseConfidenceScore": result.get("abuseConfidenceScore", 0),
                "totalReports": result.get("totalReports", 0),
                "countryCode": result.get("countryCode", ""),
                "isp": result.get("isp", ""),
                "domain": result.get("domain", ""),
                "isPublic": result.get("isPublic", True),
                "usageType": result.get("usageType", ""),
                "lastReportedAt": result.get("lastReportedAt"),
            }
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"Failed to reach AbuseIPDB: {exc}")


@router.get("/history")
def get_score_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization")

    history = (
        db.query(ScanScoreHistory)
        .filter(ScanScoreHistory.org_id == current_user.org_id)
        .order_by(ScanScoreHistory.scan_date.desc())
        .all()
    )

    return [
        {
            "org_id": item.org_id,
            "domain": item.domain,
            "domain_score": item.domain_score,
            "result": item.result or {},
            "scan_date": (
                item.scan_date.astimezone(timezone.utc).isoformat()
                if item.scan_date and item.scan_date.tzinfo is not None
                else item.scan_date.isoformat() if item.scan_date else None
            ),
        }
        for item in history
    ]
