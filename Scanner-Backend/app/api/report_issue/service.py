"""
Live verification + resolution helpers for the Admin Issue Review workflow.

Provides:
- Port verification (TCP socket connect → open / closed / filtered + service map)
- HTTP header verification (live GET, checks 7 security headers)
- SSL/TLS verification (real handshake, full certificate details)
- DNS verification (live lookups via socket.getaddrinfo)
- Score recalculation when an admin resolves an issue
"""
import socket
import ssl
from datetime import datetime, timezone

import httpx

VERIFY_TIMEOUT = 5  # seconds

# Port → well-known service map (audit trail enrichment)
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
}

# The 7 security headers checked during header verification
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

# Reported issue rule → ScanSummary category column
RULE_TO_CATEGORY = {
    # Application Security
    "HTTP without HTTPS": "app_security",
    "Missing CSP header": "app_security",
    "Missing HSTS header": "app_security",
    "Missing X-Frame-Options": "app_security",
    "Missing X-Content-Type-Options": "app_security",
    # Network Security
    "Risky port exposed": "network_security",
    "Unexpected open port": "network_security",
    # TLS Security
    "443 open without TLS": "tls_security",
    "Weak TLS version": "tls_security",
    "Expired TLS": "tls_security",
    # DNS Security
    "Missing NS record": "dns_security",
    "Missing MX record": "dns_security",
    "Missing TXT record": "dns_security",
    "Duplicate SPF record": "dns_security",
    "Weak SPF policy": "dns_security",
    "Missing SPF record": "dns_security",
    "Missing DMARC": "dns_security",
    "Weak DMARC policy": "dns_security",
    "Missing DKIM": "dns_security",
}


# ─── 1. Port verification ─────────────────────────────────────────────────────

def verify_port(host: str, port: int) -> dict:
    """
    Opens a TCP socket connection to host:port (5s timeout).

    Returns: open / closed / filtered plus the mapped service name.
    """
    result = {
        "type": "port",
        "host": host,
        "port": port,
        "service": PORT_SERVICE_MAP.get(port, "unknown"),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with socket.create_connection((host, port), timeout=VERIFY_TIMEOUT) as sock:
            sock.settimeout(VERIFY_TIMEOUT)
            result["status"] = "open"
    except socket.timeout:
        # No response — traffic likely filtered/dropped by a firewall
        result["status"] = "filtered"
    except ConnectionRefusedError:
        result["status"] = "closed"
    except OSError:
        result["status"] = "filtered"
    return result


# ─── 2. HTTP header verification ──────────────────────────────────────────────

async def verify_http_headers(subdomain: str) -> dict:
    """
    Sends a live HTTP GET request and reports present/missing for each of the
    7 security headers. Tries HTTPS first, falls back to HTTP.
    """
    headers_found = {}
    status_code = None
    url_used = None

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=VERIFY_TIMEOUT,
                verify=False,  # cert validity is checked separately in the TLS path
            ) as client:
                resp = await client.get(url)
                status_code = resp.status_code
                url_used = str(resp.url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                headers_found = {
                    h: ("present" if h in headers else "missing") for h in SECURITY_HEADERS
                }
                break
        except (httpx.ConnectError, httpx.TimeoutException):
            continue

    if status_code is None:
        headers_found = {h: "missing" for h in SECURITY_HEADERS}

    return {
        "type": "header",
        "host": subdomain,
        "url": url_used,
        "status_code": status_code,
        "headers": headers_found,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── 3. SSL/TLS verification ──────────────────────────────────────────────────

def verify_tls(subdomain: str) -> dict:
    """
    Establishes a real SSL connection to :443 and parses the full certificate.

    Returns subject, issuer, validity, SANs, TLS version and cipher.
    """
    result = {
        "type": "tls",
        "host": subdomain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((subdomain, 443), timeout=VERIFY_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=subdomain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    result.update({
                        "status": "error",
                        "error": "Could not parse a certificate from the server",
                    })
                    return result
                cipher = ssock.cipher() or (None, None, None)

                def _components(entries):
                    out = {}
                    for item in entries or []:
                        if not item:
                            continue
                        try:
                            pair = item[0]
                            if pair and len(pair) >= 2:
                                out[pair[0]] = pair[1]
                        except Exception:
                            continue
                    return out

                result.update({
                    "status": "ok",
                    "tls_version": ssock.version(),
                    "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]},
                    "subject": _components(cert.get("subject")),
                    "issuer": _components(cert.get("issuer")),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "sans": [san[1] for san in cert.get("subjectAltName", [])],
                    "serial_number": cert.get("serialNumber"),
                })
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.update({"status": "error", "error": str(exc)})

    return result


# ─── 4. DNS verification ──────────────────────────────────────────────────────

def verify_dns(domain: str, record_type: str = "A") -> dict:
    """
    Performs live DNS lookups via socket.getaddrinfo.

    Supports A, AAAA or ANY (resolves both).
    """
    result = {
        "type": "dns",
        "host": domain,
        "record_type": (record_type or "A").upper(),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    rt = (record_type or "A").upper()
    families = []
    if rt in ("A", "ANY"):
        families.append((socket.AF_INET, "A"))
    if rt in ("AAAA", "ANY"):
        families.append((socket.AF_INET6, "AAAA"))

    resolved = []
    for family, label in families:
        try:
            infos = socket.getaddrinfo(domain, None, family)
            ips = sorted({info[4][0] for info in infos})
            resolved.append({"type": label, "addresses": ips})
        except socket.gaierror:
            resolved.append({"type": label, "addresses": []})

    result["results"] = resolved
    result["status"] = "ok" if any(r["addresses"] for r in resolved) else "no_records"
    return result


# ─── 5. Score recalculation on resolution ─────────────────────────────────────

def resolve_issue_score(db, issue) -> dict:
    """
    Called when an admin resolves an issue.

    1. Removes the finding from the ScanSummary category.
    2. Recalculates the domain score using severity-adjusted penalties.
    3. If the finding can't be found in scan data, applies a fixed +2 bonus.
    """
    from app.db.models import ScanSummary
    from app.api.fix.service import _recalculate_score
    from app.api.analyzer.controller import get_cvss_severity

    summary = db.query(ScanSummary).filter(
        ScanSummary.domain == (issue.domain or "").strip().lower()
    ).first()

    if not summary:
        return {
            "success": False,
            "removed": False,
            "bonus_applied": False,
            "domain_score": None,
            "severity": None,
        }

    category = RULE_TO_CATEGORY.get(issue.rule)
    removed = False

    if category:
        category_data = dict(getattr(summary, category) or {})
        findings = list(category_data.get(issue.rule, []))
        target = (issue.subdomain or issue.domain or "").strip().lower()
        updated = [
            f for f in findings
            if (f.get("subdomain") or "").strip().lower() != target
        ]
        if len(updated) != len(findings):
            if updated:
                category_data[issue.rule] = updated
            else:
                category_data.pop(issue.rule, None)
            setattr(summary, category, category_data or None)
            removed = True

    if removed:
        _recalculate_score(summary)
        bonus_applied = False
    else:
        # Finding not found → fixed +2 point bonus (capped at 100)
        summary.domain_score = min(100, (summary.domain_score or 0) + 2)
        summary.severity = get_cvss_severity(summary.domain_score)["severity"]
        bonus_applied = True

    db.add(summary)
    db.commit()
    db.refresh(summary)

    return {
        "success": True,
        "removed": removed,
        "bonus_applied": bonus_applied,
        "domain_score": summary.domain_score,
        "severity": summary.severity,
    }
