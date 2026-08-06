"""
VAPT normalizer — turns raw parsed findings into a clean, report-ready structure.

Pipeline:
1. ``filter_real_issues`` — drop informational noise (severity "info") and
   empty rows, so real vulnerabilities (Critical / High / Medium / Low) reach
   the report & risk score.
2. ``categorize`` — auto-classify each finding (Web App, TLS/SSL, DNS,
   Network, Mail Security, OS/Host, Application).
3. ``consolidate_issues`` — merge the same issue found on multiple hosts into
   a single entry carrying ``affected_hosts`` + ``host_count`` (Nessus-style).
4. ``compute_risk_score`` — a transparent 0-100 risk index based on the worst
   severity and the average severity density of the remaining findings.
"""

SEVERITY_LABELS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# ─── Auto-categorization ──────────────────────────────────────────────────────
# Heuristic keyword rules evaluated in order (first match wins). The haystack is
# the title + plugin family + description of each finding.

CATEGORY_RULES: list[tuple[str, list[str]]] = [
    ("Mail Security", [
        "mail", "smtp", "spf", "dkim", "dmarc", "email", "exim", "postfix",
        "sendmail", "mx record", "imap", "pop3", "message transfer",
    ]),
    ("DNS", [
        "dns", "bind", "zone transfer", "resolver", "ns record", "nameserver",
        "dnssec", "dns server",
    ]),
    ("TLS/SSL", [
        "tls", "ssl", "certificate", "https", "openssl", "heartbleed",
        "cipher", "poodle", "sweet32", "sslv3", "tlsv1", "cert", "handshake",
        "sni", "ca-", "x.509",
    ]),
    ("Web App", [
        "web", "http", "apache", "nginx", "iis", "xss", "csrf", "sql injection",
        "php", "cgi", "cookie", "header", "clickjack", "directory listing",
        "x-frame", "csp", "hsts", "webserver", "http server", "servlet",
        "webapp", "url", "cors", "frame", "svg", "javascript",
    ]),
    ("Network", [
        "port", "tcp", "udp", "snmp", "telnet", "ftp", "samba", "smb", "nfs",
        "router", "firewall", "cisco", "network", "icmp", "ssh", "rdp", "vnc",
        "sip", "switching", "default snmp",
    ]),
    ("OS/Host", [
        "linux", "windows", "kernel", "ubuntu", "debian", "centos", "rhel",
        "red hat", "unpatched", "service pack", "local", "privilege",
        "operating system", "mount", "grub", "bios", "os ",
    ]),
    ("Application", [
        "application", "oracle", "mysql", "mssql", "postgres", "tomcat",
        "jenkins", "wordpress", "joomla", "drupal", "phpmyadmin", "docker",
        "kubernetes", "redis", "mongodb", "elasticsearch", "software",
    ]),
]

DEFAULT_CATEGORY = "Application"


def categorize(finding: dict) -> str:
    haystack = " ".join(
        str(finding.get(k) or "") for k in ("title", "plugin_family", "description")
    ).lower()
    for category, keywords in CATEGORY_RULES:
        if any(kw in haystack for kw in keywords):
            return category
    return DEFAULT_CATEGORY


# ─── Real issues only ─────────────────────────────────────────────────────────

def filter_real_issues(raw_findings: list[dict]) -> list[dict]:
    """Keep only findings that represent a real vulnerability.

    Informational ("info") entries — open ports with no risk, fine TLS versions,
    "secure web service running", etc. — are excluded, as are completely empty
    rows that carry no title / description / CVE. Low and above are kept so
    even a clean scan still produces a report.
    """
    kept: list[dict] = []
    for finding in raw_findings:
        if finding.get("severity", 0) <= 0:
            continue
        title = (finding.get("title") or "").strip()
        description = (finding.get("description") or "").strip()
        if not title and not description and not finding.get("cves"):
            continue
        kept.append(finding)
    return kept


# ─── Consolidation ────────────────────────────────────────────────────────────

def _consolidation_key(finding: dict) -> tuple:
    """Group key — same plugin (or title) + port + protocol across hosts."""
    if finding.get("plugin_id"):
        base = str(finding["plugin_id"]).strip().lower()
    else:
        base = re_normalize_title(str(finding.get("title") or "")).lower()
    return (base, finding.get("port"), (finding.get("protocol") or "").lower())


def re_normalize_title(title: str) -> str:
    import re
    return re.sub(r"\s+", " ", title).strip()


def consolidate_issues(filtered: list[dict]) -> list[dict]:
    """Merge the same issue found on multiple hosts into one normalized entry.

    The merged entry keeps the full list of affected addresses in
    ``affected_hosts`` and a ``host_count`` — the classic Nessus layout.
    """
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []

    for finding in filtered:
        key = _consolidation_key(finding)
        if key not in groups:
            groups[key] = {
                "title": (finding.get("title") or "Untitled finding").strip(),
                "severity": finding.get("severity", 0),
                "severity_label": (
                    finding.get("severity_label")
                    or SEVERITY_LABELS.get(finding.get("severity", 0), "info")
                ),
                "cvss_score": finding.get("cvss_score"),
                "cvss_vector": finding.get("cvss_vector") or "",
                "category": finding.get("category") or categorize(finding),
                "port": finding.get("port"),
                "protocol": finding.get("protocol") or "",
                "service": finding.get("service") or "",
                "plugin_id": finding.get("plugin_id") or "",
                "plugin_family": finding.get("plugin_family") or "",
                "description": finding.get("description") or "",
                "synopsis": finding.get("synopsis") or "",
                "solution": finding.get("solution") or "",
                "references": [],
                "cves": [],
                "affected_hosts": [],
                "host_outputs": [],
                "evidence": "",
            }
            order.append(key)

        entry = groups[key]
        host = (finding.get("host") or "").strip()
        if host and host not in entry["affected_hosts"]:
            entry["affected_hosts"].append(host)

        for ref in finding.get("references") or []:
            if ref and ref not in entry["references"]:
                entry["references"].append(ref)
        for cve in finding.get("cves") or []:
            if cve and cve not in entry["cves"]:
                entry["cves"].append(cve)

        evidence = (finding.get("evidence") or "").strip()
        if evidence:
            host_output = {"host": host, "output": evidence}
            if host_output not in entry["host_outputs"]:
                entry["host_outputs"].append(host_output)

        # Prefer the most detailed description/solution we've seen.
        if len(entry["description"]) < len(finding.get("description") or ""):
            entry["description"] = finding.get("description") or ""
        if len(entry["solution"]) < len(finding.get("solution") or ""):
            entry["solution"] = finding.get("solution") or ""

    # Sort by severity (desc), then CVSS score (desc), then title.
    consolidated = [groups[k] for k in order]
    consolidated.sort(
        key=lambda f: (f["severity"], f.get("cvss_score") or 0),
        reverse=True,
    )

    for index, finding in enumerate(consolidated, start=1):
        finding["id"] = f"F{index:03d}"
        finding["host_count"] = len(finding["affected_hosts"])
        finding["evidence"] = "\n\n".join(
            o.get("output", "") for o in finding["host_outputs"]
        ).strip()
        # A default PoC placeholder when the source provided no plugin output.
        if not finding["evidence"] and finding["synopsis"]:
            finding["evidence"] = finding["synopsis"]

    return consolidated


# ─── Risk scoring (0-100) ─────────────────────────────────────────────────────

# Weights for the average severity "density" of the report.
SEVERITY_DENSITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def compute_risk_score(findings: list[dict]) -> tuple[int, str]:
    """
    Transparent 0-100 risk index.

    score = min(100, 18 * worst_severity + 10 * average_density)

    - ``18 * worst_severity`` anchors the score to the most severe finding
      (a single critical finding alone scores 72).
    - ``10 * average_density`` (0-40) reflects how many high-severity findings
      are present — a critical-heavy report approaches 100.
    """
    if not findings:
        return 0, "none"

    worst = max(f["severity"] for f in findings)
    avg_density = sum(SEVERITY_DENSITY.get(f.get("severity_label"), 0) for f in findings) / len(findings)

    score = min(100, round(18 * worst + 10 * avg_density))

    if score >= 80:
        label = "critical"
    elif score >= 60:
        label = "high"
    elif score >= 40:
        label = "medium"
    elif score >= 20:
        label = "low"
    else:
        label = "none"
    return score, label


# ─── Full normalization ───────────────────────────────────────────────────────

def normalize_import(raw_findings: list[dict], source_tool: str = "generic") -> dict:
    """Normalize raw findings into the full report payload stored on the import."""
    filtered = filter_real_issues(raw_findings)
    excluded_info = len(raw_findings) - len(filtered)

    for finding in filtered:
        finding["category"] = categorize(finding)

    findings = consolidate_issues(filtered)

    severity_distribution = {label: 0 for label in SEVERITY_ORDER}
    category_distribution: dict[str, int] = {}
    for finding in findings:
        severity_distribution[finding["severity_label"]] = (
            severity_distribution.get(finding["severity_label"], 0) + 1
        )
        cat = finding.get("category") or DEFAULT_CATEGORY
        category_distribution[cat] = category_distribution.get(cat, 0) + 1

    hosts = sorted({
        host
        for finding in findings
        for host in finding.get("affected_hosts", [])
    })

    # Per-host operating system, captured by the parsers (Nessus tags / an
    # "OS" column). Used for the report's Asset Summary section.
    host_os: dict[str, str] = {}
    for finding in filtered:
        host = (finding.get("host") or "").strip()
        if host:
            host_os.setdefault(host, (finding.get("os") or "").strip())

    host_list = []
    for host in hosts:
        host_list.append({
            "host": host,
            "os": host_os.get(host, ""),
            "finding_count": sum(
                1 for f in findings if host in f.get("affected_hosts", [])
            ),
        })

    risk_score, overall_severity = compute_risk_score(findings)

    summary = {
        "file_name": "",
        "source_tool": source_tool,
        "raw_findings_parsed": len(raw_findings),
        "excluded_info_findings": excluded_info,
        "real_findings": len(findings),
        "unique_hosts": len(hosts),
        "hosts": host_list,
        "risk_score": risk_score,
        "severity": overall_severity,
        "note": (
            "Informational findings are excluded automatically so the report "
            "focuses on real vulnerabilities."
        ),
    }

    return {
        "summary": summary,
        "severity_distribution": severity_distribution,
        "category_distribution": category_distribution,
        "findings": findings,
        "unique_hosts": len(hosts),
        "hosts": host_list,
        "risk_score": risk_score,
        "severity": overall_severity,
        "total_findings": len(findings),
    }
