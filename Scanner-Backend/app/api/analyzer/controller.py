from collections import defaultdict
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException
from sqlalchemy import desc, text
import json
import uuid
START_SCORE = 100

SAFE_PORTS = {80, 443, 993, 995, 465, 587}
EXPECTED_PORTS = {80, 443, 993, 995, 465, 587, 8443}
RISKY_PORTS = {8080, 8081, 8888, 3000, 5000}

OLD_TLS = {"tls10", "tls11"}

CATEGORY_RULES = {
    "DNS Security": [
        "Missing NS record",
        "Missing TXT record",
        "Missing MX record"
    ],
    "Application Security": [
        "HTTP without HTTPS",
        "Missing CSP header",
        "Missing HSTS header",
        "Missing X-Frame-Options",
        "Missing X-Content-Type-Options"
    ],
    "Network Security": [
        "Risky port exposed",
        "Unexpected open port"
    ],
    "TLS Security": [
        "443 open without TLS",
        "Weak TLS version",
        "Expired TLS"
    ]
}


def evaluate_dns(dns, is_root=False, has_mail_service=False):
    penalty = 0
    issues = []

    if not dns:
        return penalty, issues

    if not is_root:
        return penalty, issues

    # NS check always on root
    if not dns.get("ns"):
        penalty += 2
        issues.append("Missing NS record")

    # MX and TXT only if domain has mail service
    if has_mail_service:
        if not dns.get("mx"):
            penalty += 2
            issues.append("Missing MX record")

        if not dns.get("txt"):
            penalty += 1
            issues.append("Missing TXT record")

    return penalty, issues


def evaluate_http(http):
    penalty = 0
    issues = []

    if not http:
        return penalty, issues

    scheme = http.get("scheme")
    tls = http.get("tls", {})

    if scheme == "http" and not tls.get("enabled"):
        penalty += 20
        issues.append("HTTP without HTTPS")

    headers = http.get("headers", {})

    if not headers.get("content_security_policy"):
        penalty += 3
        issues.append("Missing CSP header")

    if not headers.get("strict_transport_security"):
        penalty += 4
        issues.append("Missing HSTS header")

    if not headers.get("x_frame_options"):
        penalty += 2
        issues.append("Missing X-Frame-Options")

    if not headers.get("x_content_type_options"):
        penalty += 2
        issues.append("Missing X-Content-Type-Options")

    return penalty, issues


def evaluate_port(port):
    penalty = 0
    issues = []

    p = port.get("port")

    if not p:
        return penalty, issues

    if p in RISKY_PORTS:
        penalty += 10
        issues.append(f"Risky port exposed {p}")

    elif p not in EXPECTED_PORTS:
        penalty += 8
        issues.append(f"Unexpected open port {p}")

    return penalty, issues


def evaluate_tls(port):
    penalty = 0
    issues = []

    tls = port.get("tls")

    if not tls:
        if port.get("port") == 443:
            penalty += 20
            issues.append("443 open without TLS")
        return penalty, issues

    # tls exists but Enabled is explicitly False
    if isinstance(tls, dict) and tls.get("enabled") is False:
        if port.get("port") == 443:
            penalty += 20
            issues.append("443 open without TLS")
        return penalty, issues

    version = (tls.get("version") or "").lower()

    if tls.get("expired"):
        penalty += 20
        issues.append("Expired TLS")

    if version in OLD_TLS:
        penalty += 15
        issues.append(f"Weak TLS version {version}")

    return penalty, issues


def get_cvss_severity(score):

    # convert 0-100 → 0-10 scale
    cvss_score = round((100 - score) / 10, 1)

    if cvss_score >= 9.0:
        severity = "Critical"
    elif cvss_score >= 7.0:
        severity = "High"
    elif cvss_score >= 4.0:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "cvss_score": cvss_score,
        "severity": severity
    }

def score_subdomain(asset, root_domain=None, has_mail_service=False):
    score = START_SCORE
    issues = []

    dns = asset.get("dns_collection")
    http = asset.get("http_collection")
    ports = asset.get("port_collection", [])

    subdomain = asset.get("subdomain", "")
    is_root = (subdomain == root_domain)

    dns_pen, dns_issues = evaluate_dns(dns, is_root=is_root, has_mail_service=has_mail_service)
    score -= dns_pen
    issues.extend(dns_issues)

    http_pen, http_issues = evaluate_http(http)
    score -= http_pen
    issues.extend(http_issues)

    for port in ports:
        p_pen, p_issues = evaluate_port(port)
        score -= p_pen
        issues.extend(p_issues)

        tls_pen, tls_issues = evaluate_tls(port)
        score -= tls_pen
        issues.extend(tls_issues)

    score = max(score, 0)

    return {
        "subdomain": asset.get("subdomain", "unknown"),
        "score": score,
        "issues": issues
    }


def score_domain(data, root_domain=None, has_mail_service=False):
    results = []
    scores = []

    for asset in data:
        r = score_subdomain(asset, root_domain=root_domain, has_mail_service=has_mail_service)
        results.append(r)
        scores.append(r["score"])

    domain_score = int(sum(scores) / len(scores)) if scores else 0

    cvss = get_cvss_severity(domain_score)

    return {
        "domain_score": domain_score,
        "cvss_score": cvss["cvss_score"],
        "severity": cvss["severity"],
        "subdomains": results
    }


def categorize_issues(results, raw_data):
    categorized = defaultdict(lambda: defaultdict(list))
    asset_map = {a.get("subdomain"): a for a in raw_data}
    for sub in results["subdomains"]:
        subdomain = sub["subdomain"]
        asset = asset_map.get(subdomain, {})
        ip = None
        dns = asset.get("dns_collection", {})
        if dns and dns.get("a"):
            ip = dns.get("a")[0]

        ports = [p.get("port") for p in asset.get("port_collection", []) if p.get("port")]

        for issue in sub["issues"]:

            for category, patterns in CATEGORY_RULES.items():

                for pattern in patterns:

                    if issue.startswith(pattern):

                        # Base entry (default)
                        severity_data = get_cvss_severity(sub["score"])

                        entry = {
                            "subdomain": subdomain,
                            "ip": ip,
                            "severity": severity_data["severity"]
                        }
                        # Only add port for Network Security
                        if category == "Network Security":

                            issue_port = None
                            for p in ports:
                                if str(p) in issue:
                                    issue_port = p
                                    break

                            entry["port"] = issue_port

                        # Avoid duplicates
                        if entry not in categorized[category][pattern]:
                            categorized[category][pattern].append(entry)
    return categorized

def evaluate_dns_security(host: dict, subdomains: list[dict]) -> dict:
    findings = defaultdict(list)
    root_domain = host.get("domain")
    mail_security = host.get("mail_security", {})

    root_sub = next(
        (s for s in subdomains if s.get("subdomain") == root_domain),
        None,
    )
    if not root_sub:
        return {}

    dns = root_sub.get("dns_collection") or {}
    ip = (dns.get("a") or [None])[0]
    base = {"subdomain": root_domain, "ip": ip}

    txt_records = dns.get("txt") or []
    spf_count = sum(
        1 for t in txt_records if isinstance(t, str) and t.startswith("v=spf1")
    )
    if spf_count > 1:
        findings["Duplicate SPF record"].append({**base, "severity": "Medium"})

    spf = mail_security.get("spf", {})
    if spf.get("exists") and spf.get("policy") == "soft":
        findings["Weak SPF policy"].append({**base, "severity": "Low"})

    if not spf.get("exists"):
        findings["Missing SPF record"].append({**base, "severity": "High"})

    dmarc = mail_security.get("dmarc", {})
    if not dmarc.get("exists"):
        findings["Missing DMARC"].append({**base, "severity": "High"})

    if dmarc.get("exists") and dmarc.get("policy") in ("none", "quarantine"):
        findings["Weak DMARC policy"].append({**base, "severity": "Medium"})

    dkim = mail_security.get("dkim", {})
    if not dkim.get("exists"):
        findings["Missing DKIM"].append({**base, "severity": "Medium"})

    ns = dns.get("ns")
    if not ns:
        findings["Missing NS record"].append({**base, "severity": "High"})

    return dict(findings)


def _to_plain_dict(value):
    if not value:
        return {}
    return {
        check: findings
        for check, findings in value.items()
        if findings
    }


def calculate_and_store_summary(db: Session, org_id: str, target: str, raw_data: dict):
    host = raw_data.get("host", {})
    subdomains = raw_data.get("subdomains", [])

    mail_security = host.get("mail_security", {})
    has_mail_service = bool(
        mail_security.get("spf") or
        mail_security.get("dkim") or
        mail_security.get("mx")
    )
    root_domain = host.get("domain") or target

    scoring = score_domain(subdomains, root_domain=root_domain, has_mail_service=has_mail_service)
    categorized = categorize_issues(scoring, subdomains)

    dns_security = evaluate_dns_security(host, subdomains)
    if dns_security:
        for check_name, check_findings in dns_security.items():
            categorized["DNS Security"][check_name] = check_findings

    app_security = _to_plain_dict(categorized.get("Application Security"))
    network_security = _to_plain_dict(categorized.get("Network Security"))
    tls_security = _to_plain_dict(categorized.get("TLS Security"))
    dns_security = _to_plain_dict(categorized.get("DNS Security"))

    ips_of_scan = get_ips_from_scan(subdomains)

    existing_summary = db.execute(
        text(
            """
            SELECT org_id
            FROM scan_summary
            WHERE domain = :domain
            LIMIT 1
            """
        ),
        {"domain": root_domain},
    ).fetchone()

    existing_org_id = None
    if existing_summary:
        try:
            existing_org_id = existing_summary[0]
        except Exception:
            existing_org_id = None

    # prefer provided org_id, otherwise fall back to existing summary org_id
    org_id_to_use = org_id or existing_org_id

    if existing_summary:
        db.execute(
            text(
                """
                UPDATE scan_summary
                SET org_id = COALESCE(:org_id, org_id),
                    domain_score = :domain_score,
                    domain_criticality = COALESCE(:domain_criticality, domain_criticality),
                    severity = :severity,
                    mail_security = :mail_security,
                    app_security = :app_security,
                    network_security = :network_security,
                    tls_security = :tls_security,
                    dns_security = :dns_security,
                    ips = :ips
                WHERE domain = :domain
                """
            ),
            {
                "org_id": org_id,
                "domain_score": scoring["domain_score"],
                "severity": scoring["severity"],
                "domain_criticality": "medium",
                "mail_security": json.dumps(mail_security),
                "app_security": json.dumps(app_security),
                "network_security": json.dumps(network_security),
                "tls_security": json.dumps(tls_security),
                "dns_security": json.dumps(dns_security),
                "ips": json.dumps(ips_of_scan),
                "domain": root_domain,
            },
        )
    else:
        # If we still don't have an org_id, try to derive it from organizations or users
        if org_id_to_use is None:
            # Try organizations where domain JSONB contains the domain
            try:
                org_row = db.execute(
                    text(
                        "SELECT org_id FROM organizations WHERE domain @> :domain_json LIMIT 1"
                    ),
                    {"domain_json": json.dumps([root_domain])},
                ).fetchone()
                if org_row:
                    org_id_to_use = org_row[0]
            except Exception:
                org_id_to_use = None

        if org_id_to_use is None:
            # Fallback: try users.pending_registration_domain
            try:
                user_row = db.execute(
                    text(
                        "SELECT org_id FROM users WHERE pending_registration_domain = :domain LIMIT 1"
                    ),
                    {"domain": root_domain},
                ).fetchone()
                if user_row:
                    org_id_to_use = user_row[0]
            except Exception:
                org_id_to_use = None

        if org_id_to_use is None:
            raise HTTPException(status_code=400, detail="org_id missing for new scan summary")

        db.execute(
            text(
                """
                INSERT INTO scan_summary (
                    domain,
                    org_id,
                    domain_score,
                    domain_criticality,
                    severity,
                    mail_security,
                    app_security,
                    network_security,
                    tls_security,
                    dns_security,
                    ips
                ) VALUES (
                    :domain,
                    :org_id,
                    :domain_score,
                    :domain_criticality,
                    :severity,
                    :mail_security,
                    :app_security,
                    :network_security,
                    :tls_security,
                    :dns_security,
                    :ips
                )
                """
            ),
            {
                "domain": root_domain,
                "org_id": org_id_to_use,
                "domain_score": scoring["domain_score"],
                "domain_criticality": "medium",
                "severity": scoring["severity"],
                "mail_security": json.dumps(mail_security),
                "app_security": json.dumps(app_security),
                "network_security": json.dumps(network_security),
                "tls_security": json.dumps(tls_security),
                "dns_security": json.dumps(dns_security),
                "ips": json.dumps(ips_of_scan),
            },
        )

    db.commit()

    # Insert scan history only if we have an org_id (table enforces NOT NULL)
    if org_id_to_use:
        history_result = {
            "domain": root_domain,
            "domain_score": scoring["domain_score"],
            "severity": scoring["severity"],
            "host": {
                "domain": root_domain,
                "mail_security": mail_security or {},
            },
            "categorized_vulnerabilities": {
                "Application Security": app_security or {},
                "Network Security": network_security or {},
                "TLS Security": tls_security or {},
                "DNS Security": dns_security or {},
            },
            "ips": ips_of_scan or [],
            "subdomains": scoring.get("subdomains") or [],
            "raw_scan": raw_data or {},
        }

        db.execute(
            text(
                """
                INSERT INTO scan_score_history (_id, org_id, domain, domain_score, result, scan_date)
                VALUES (:_id, :org_id, :domain, :domain_score, :result, :scan_date)
                """
            ),
            {
                "_id": str(uuid.uuid4()),
                "org_id": org_id_to_use,
                "domain": root_domain,
                "domain_score": scoring["domain_score"],
                "result": json.dumps(history_result),
                "scan_date": datetime.now(timezone.utc),
            },
        )
        db.commit()

def get_ips_from_scan(subdomains: list):
    ips = []

    for item in subdomains:
        http_data = item.get("http_collection", {})

        ip = http_data.get("ip")
        if ip:
            ips.append(ip)
    return list(set(ips))