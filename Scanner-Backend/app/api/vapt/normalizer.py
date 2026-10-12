"""
VAPT normalizer — turns raw parsed findings into a clean, report-ready structure.

Pipeline:
1. ``filter_reportable_findings`` — keep titled findings, including informational
   entries, while dropping empty rows.
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

def filter_reportable_findings(raw_findings: list[dict]) -> list[dict]:
    """Keep all titled findings and discard only empty parser rows."""
    kept: list[dict] = []
    for finding in raw_findings:
        title = (finding.get("title") or "").strip()
        description = (finding.get("description") or "").strip()
        if not title and not description and not finding.get("cves"):
            continue
        kept.append(finding)
    return kept


# ─── Consolidation ────────────────────────────────────────────────────────────

def finding_group_key(finding: dict) -> tuple:
    """Group findings by normalized name, independent of asset and transport."""
    title = re_normalize_title(str(finding.get("title") or "")).casefold()
    if title:
        return (title,)

    plugin_id = str(finding.get("plugin_id") or finding.get("vuln_id") or "").strip().lower()
    description = re_normalize_title(str(finding.get("description") or "")).lower()
    cves = tuple(sorted(
        str(cve).strip().lower()
        for cve in (finding.get("cves") or [])
        if cve
    ))
    return (plugin_id, description, cves)


def re_normalize_title(title: str) -> str:
    import re
    return re.sub(r"\s+", " ", title).strip()


def consolidate_issues(filtered: list[dict]) -> list[dict]:
    """Merge same-name findings while retaining all asset and transport details."""
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []

    for finding in filtered:
        key = finding_group_key(finding)
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
                "ports": [],
                "protocol": finding.get("protocol") or "",
                "protocols": [],
                "service": finding.get("service") or "",
                "plugin_id": finding.get("plugin_id") or "",
                "plugin_family": finding.get("plugin_family") or "",
                "vuln_id": finding.get("vuln_id") or "",
                "result_id": finding.get("result_id") or "",
                "confidence": finding.get("confidence"),
                "last_seen": finding.get("last_seen") or "",
                "target_id": finding.get("target_id") or "",
                "description": finding.get("description") or "",
                "synopsis": finding.get("synopsis") or "",
                "solution": finding.get("solution") or "",
                "references": [],
                "cves": [],
                "affected_hosts": [],
                "affected_assets": [],
                "mac_addresses": [],
                "host_outputs": [],
                "evidence": "",
                "status": (finding.get("status") or "pending").strip() or "pending",
                "_statuses": set(),
                "comment": (finding.get("comment") or "").strip(),
                "mac_address": "",
                "hostname": (finding.get("hostname") or "").strip(),
                "operating_system": (finding.get("operating_system") or "").strip(),
                "remarks": (finding.get("remarks") or "").strip(),
                "affected_detail": finding.get("affected_detail") or "",
                "http_request": finding.get("http_request") or "",
                "http_response": finding.get("http_response") or "",
                "request_headers": finding.get("request_headers") or "",
                "response_headers": finding.get("response_headers") or "",
                "request_body": finding.get("request_body") or "",
                "response_body": finding.get("response_body") or "",
            }
            order.append(key)

        entry = groups[key]
        entry["_statuses"].add(
            (finding.get("status") or "pending").strip() or "pending"
        )
        host = (finding.get("host") or "").strip()
        if host and host not in entry["affected_hosts"]:
            entry["affected_hosts"].append(host)

        mac_address = (finding.get("mac_address") or "").strip()
        hostname = (finding.get("hostname") or "").strip()
        operating_system = (
            finding.get("operating_system") or finding.get("os") or ""
        ).strip()
        asset_identity = host.casefold() or mac_address.casefold()
        if asset_identity:
            asset = next(
                (
                    item for item in entry["affected_assets"]
                    if (item["host"].casefold() or item["mac_address"].casefold()) == asset_identity
                ),
                None,
            )
            if asset is None:
                asset = {
                    "host": host,
                    "mac_address": mac_address,
                    "hostname": hostname,
                    "operating_system": operating_system,
                    "protocols": [],
                    "ports": [],
                }
                entry["affected_assets"].append(asset)
            elif not asset["operating_system"] and operating_system:
                asset["operating_system"] = operating_system
            if not asset["hostname"] and hostname:
                asset["hostname"] = hostname
            existing_macs = [
                value.strip()
                for value in str(asset["mac_address"] or "").split(",")
                if value.strip()
            ]
            if mac_address and mac_address.casefold() not in {
                value.casefold() for value in existing_macs
            }:
                asset["mac_address"] = ", ".join([*existing_macs, mac_address])

            protocol = str(finding.get("protocol") or "").strip()
            if protocol and protocol.casefold() not in {
                value.casefold() for value in asset["protocols"]
            }:
                asset["protocols"].append(protocol)
            port = finding.get("port")
            if port is not None and port not in asset["ports"]:
                asset["ports"].append(port)

        if mac_address and mac_address.casefold() not in {
            value.casefold() for value in entry["mac_addresses"]
        }:
            entry["mac_addresses"].append(mac_address)
        protocol = str(finding.get("protocol") or "").strip()
        if protocol and protocol.casefold() not in {
            value.casefold() for value in entry["protocols"]
        }:
            entry["protocols"].append(protocol)
        port = finding.get("port")
        if port is not None and port not in entry["ports"]:
            entry["ports"].append(port)

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

        if not entry.get("comment") and (finding.get("comment") or "").strip():
            entry["comment"] = (finding.get("comment") or "").strip()
        if not entry.get("hostname") and (finding.get("hostname") or "").strip():
            entry["hostname"] = (finding.get("hostname") or "").strip()
        if not entry.get("operating_system") and (finding.get("operating_system") or "").strip():
            entry["operating_system"] = (finding.get("operating_system") or "").strip()
        if not entry.get("remarks") and (finding.get("remarks") or "").strip():
            entry["remarks"] = (finding.get("remarks") or "").strip()
        for field in ("affected_detail", "http_request", "http_response", "request_headers", "response_headers", "request_body", "response_body"):
            if len(str(entry.get(field) or "")) < len(str(finding.get(field) or "")):
                entry[field] = finding.get(field) or ""
        for field in ("vuln_id", "result_id", "last_seen", "target_id"):
            if not entry.get(field) and finding.get(field):
                entry[field] = finding[field]
        if entry.get("confidence") is None and finding.get("confidence") is not None:
            entry["confidence"] = finding["confidence"]
        for field in ("port", "protocol", "service"):
            if not entry.get(field) and finding.get(field):
                entry[field] = finding[field]

        if finding.get("severity", 0) > entry.get("severity", 0):
            entry["severity"] = finding["severity"]
            entry["severity_label"] = (
                finding.get("severity_label")
                or SEVERITY_LABELS.get(finding["severity"], "info")
            )
        if (
            isinstance(finding.get("cvss_score"), (int, float))
            and (
                not isinstance(entry.get("cvss_score"), (int, float))
                or finding["cvss_score"] > entry["cvss_score"]
            )
        ):
            entry["cvss_score"] = finding["cvss_score"]

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
        finding["host_count"] = len(finding["affected_hosts"] or finding["affected_assets"])
        finding["mac_address"] = ", ".join(finding.pop("mac_addresses"))
        if len(finding["_statuses"]) != 1:
            finding["status"] = "pending"
        else:
            finding["status"] = next(iter(finding["_statuses"]))
        del finding["_statuses"]
        finding["protocols"].sort(key=str.casefold)
        finding["ports"].sort(key=lambda value: (str(type(value)), value))
        for asset in finding["affected_assets"]:
            asset["protocols"].sort(key=str.casefold)
            asset["ports"].sort(key=lambda value: (str(type(value)), value))
        finding["evidence"] = "\n\n".join(
            o.get("output", "") for o in finding["host_outputs"]
        ).strip()
        # A default PoC placeholder when the source provided no plugin output.
        if not finding["evidence"] and finding["synopsis"]:
            finding["evidence"] = finding["synopsis"]

    return consolidated


def group_stored_findings(findings: list[dict]) -> list[dict]:
    """Group previously stored per-asset rows for consistent report display."""
    grouped: dict[tuple, dict] = {}
    order: list[tuple] = []

    for finding in findings:
        key = finding_group_key(finding)
        if key not in grouped:
            grouped[key] = {
                **finding,
                "affected_hosts": [],
                "affected_assets": [],
                "mac_addresses": [],
                "protocols": [],
                "ports": [],
                "grouped_finding_ids": [],
                "_statuses": set(),
            }
            order.append(key)

        entry = grouped[key]
        entry["_statuses"].add(
            str(finding.get("status") or "pending").strip().lower()
        )
        if finding.get("id") is not None:
            entry["grouped_finding_ids"].append(str(finding["id"]))
        entry["severity"] = max(
            entry.get("severity") or 0,
            finding.get("severity") or 0,
        )
        severity_labels = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        if severity_labels.get(str(finding.get("severity_label") or "").lower(), 0) > severity_labels.get(
            str(entry.get("severity_label") or "").lower(), 0
        ):
            entry["severity_label"] = finding.get("severity_label")
        score = finding.get("cvss_score")
        if isinstance(score, (int, float)) and (
            not isinstance(entry.get("cvss_score"), (int, float))
            or score > entry["cvss_score"]
        ):
            entry["cvss_score"] = score

        hosts = finding.get("affected_hosts") or ([finding.get("host")] if finding.get("host") else [])
        existing_assets = finding.get("affected_assets") or []
        if existing_assets:
            assets = existing_assets
        else:
            macs = [
                mac.strip()
                for mac in str(finding.get("mac_address") or "").split(",")
                if mac.strip()
            ]
            assets = [
                {
                    "host": str(host or "").strip(),
                    "mac_address": macs[index] if len(hosts) == len(macs) else (macs[0] if len(hosts) == 1 and macs else ""),
                    "hostname": finding.get("hostname") or "",
                    "operating_system": finding.get("operating_system") or finding.get("os") or "",
                    "protocols": [],
                    "ports": [],
                }
                for index, host in enumerate(hosts)
                if str(host or "").strip()
            ]

        for host in hosts:
            host = str(host or "").strip()
            if host and host.casefold() not in {value.casefold() for value in entry["affected_hosts"]}:
                entry["affected_hosts"].append(host)
        for asset in assets:
            host = str(asset.get("host") or "").strip()
            mac = str(asset.get("mac_address") or "").strip()
            identity = host.casefold() or mac.casefold()
            existing = next(
                (
                    item for item in entry["affected_assets"]
                    if (item["host"].casefold() or item["mac_address"].casefold()) == identity
                ),
                None,
            )
            if existing is None:
                existing = {
                    "host": host,
                    "mac_address": mac,
                    "hostname": asset.get("hostname") or "",
                    "operating_system": asset.get("operating_system") or "",
                    "protocols": [],
                    "ports": [],
                }
                entry["affected_assets"].append(existing)
            elif mac and mac.casefold() not in {
                value.strip().casefold()
                for value in str(existing["mac_address"] or "").split(",")
                if value.strip()
            }:
                existing["mac_address"] = ", ".join(
                    value.strip()
                    for value in [existing["mac_address"], mac]
                    if value and value.strip()
                )
            for protocol in asset.get("protocols") or []:
                if protocol and protocol.casefold() not in {value.casefold() for value in existing["protocols"]}:
                    existing["protocols"].append(protocol)
            for port in asset.get("ports") or []:
                if port not in existing["ports"]:
                    existing["ports"].append(port)

        for mac in str(finding.get("mac_address") or "").split(","):
            mac = mac.strip()
            if mac and mac.casefold() not in {value.casefold() for value in entry["mac_addresses"]}:
                entry["mac_addresses"].append(mac)
        for protocol in finding.get("protocols") or ([finding.get("protocol")] if finding.get("protocol") else []):
            if protocol and protocol.casefold() not in {value.casefold() for value in entry["protocols"]}:
                entry["protocols"].append(protocol)
        for port in finding.get("ports") or ([finding.get("port")] if finding.get("port") is not None else []):
            if port not in entry["ports"]:
                entry["ports"].append(port)

    results = []
    for entry in grouped.values():
        statuses = entry.pop("_statuses")
        entry["status"] = next(iter(statuses)) if len(statuses) == 1 else "pending"
        entry["affected_hosts"].sort(key=str.casefold)
        entry["host_count"] = len(entry["affected_hosts"] or entry["affected_assets"])
        entry["mac_address"] = ", ".join(entry.pop("mac_addresses"))
        entry["protocols"].sort(key=str.casefold)
        entry["ports"].sort(key=lambda value: (str(type(value)), value))
        results.append(entry)
    return results


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
      are present — a critical-heavy report approaches 100. Informational
      findings remain in the report but do not affect the risk score.
    """
    scored_findings = [
        finding
        for finding in findings
        if finding.get("severity_label") in SEVERITY_DENSITY
    ]
    if not scored_findings:
        return 0, "none"

    worst = max(f["severity"] for f in scored_findings)
    avg_density = sum(
        SEVERITY_DENSITY[finding["severity_label"]]
        for finding in scored_findings
    ) / len(scored_findings)

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
    filtered = filter_reportable_findings(raw_findings)
    excluded_empty_rows = len(raw_findings) - len(filtered)

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
        "excluded_info_findings": 0,
        "excluded_empty_rows": excluded_empty_rows,
        "real_findings": sum(
            finding["severity_label"] != "info"
            for finding in findings
        ),
        "report_findings": len(findings),
        "unique_hosts": len(hosts),
        "hosts": host_list,
        "risk_score": risk_score,
        "severity": overall_severity,
        "note": (
            "Informational findings are included for reference and do not "
            "require triage or affect the risk score."
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
