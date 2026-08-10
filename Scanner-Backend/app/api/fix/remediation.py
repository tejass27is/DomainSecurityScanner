#  """
# app/api/fix/remediation.py

# Returns structured, technology-aware fix guidance for every fix_type
# supported by ShieldStat.

# Called by:  POST /fix/recommendation
#             { fix_type, technologies, tls_version }
# """

from __future__ import annotations
from typing import Any



# ── Types ─────────────────────────────────────────────────────────────────────

class RemediationStep:
    """One numbered step shown in the Fix modal."""
    def __init__(self, title: str, description: str, code: str | None = None, language: str = "nginx"):
        self.title = title
        self.description = description
        self.code = code
        self.language = language

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "code": self.code,
            "language": self.language,
        }


class RemediationGuide:
    def __init__(
        self,
        fix_type: str,
        title: str,
        why_risky: str,
        steps: list[RemediationStep],
        references: list[str] | None = None,
    ):
        self.fix_type = fix_type
        self.title = title
        self.why_risky = why_risky
        self.steps = steps
        self.references = references or []

    def to_dict(self) -> dict:
        return {
            "fix_type": self.fix_type,
            "title": self.title,
            "why_risky": self.why_risky,
            "steps": [s.to_dict() for s in self.steps],
            "references": self.references,
        }


# ── Tech-aware snippet selectors ──────────────────────────────────────────────

def _nginx_or_apache(technologies: list[str], nginx_code: str, apache_code: str) -> list[RemediationStep]:
    """Return Nginx step first if nginx detected, Apache first if apache detected, else both."""
    has_nginx  = any("nginx"  in t.lower() for t in technologies)
    has_apache = any("apache" in t.lower() for t in technologies)

    nginx_step = RemediationStep(
        title="Add the header in Nginx",
        description="Place this inside your `server {}` block. Adjust values to match your app.",
        code=nginx_code,
        language="nginx",
    )
    apache_step = RemediationStep(
        title="Or add it in Apache (.htaccess)",
        description="Add this to your `.htaccess` or `<VirtualHost>` block.",
        code=apache_code,
        language="apache",
    )
    express_step = RemediationStep(
        title="Or set it in Express (Node.js)",
        description="Use the `helmet` package — it handles all security headers in one line.",
        code='const helmet = require("helmet");\napp.use(helmet());',
        language="javascript",
    )

    if has_nginx:
        return [nginx_step, apache_step, express_step]
    if has_apache:
        return [apache_step, nginx_step, express_step]
    return [nginx_step, apache_step, express_step]


# ── Per-fix-type guides ───────────────────────────────────────────────────────

def _guide_missing_csp(technologies: list[str]) -> RemediationGuide:
    nginx_code = (
        'add_header Content-Security-Policy\n'
        '  "default-src \'self\';\n'
        '   script-src \'self\' \'unsafe-inline\';\n'
        '   style-src \'self\' \'unsafe-inline\';\n'
        '   img-src \'self\' data:;\n'
        '   font-src \'self\';\n'
        '   frame-ancestors \'none\';" always;'
    )
    apache_code = (
        'Header always set Content-Security-Policy \\\n'
        '  "default-src \'self\'; script-src \'self\' \'unsafe-inline\';\\\n'
        '   style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:;\\\n'
        '   font-src \'self\'; frame-ancestors \'none\';"'
    )
    steps = _nginx_or_apache(technologies, nginx_code, apache_code)
    steps.append(RemediationStep(
        title="Verify the header is live",
        description="After deploying, run this curl command to confirm the header is present.",
        code='curl -sI https://yourdomain.com | grep -i content-security-policy',
        language="bash",
    ))
    return RemediationGuide(
        fix_type="missing_csp",
        title="Missing CSP Header",
        why_risky=(
            "Without a Content-Security-Policy header, attackers can inject malicious scripts "
            "(XSS) into your pages. The browser has no rules about which sources to trust."
        ),
        steps=steps,
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://content-security-policy.com/",
        ],
    )


def _guide_missing_hsts(technologies: list[str]) -> RemediationGuide:
    nginx_code = 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'
    apache_code = 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
    steps = _nginx_or_apache(technologies, nginx_code, apache_code)
    steps.insert(0, RemediationStep(
        title="Ensure HTTPS is fully working first",
        description=(
            "HSTS tells browsers to only use HTTPS forever. "
            "If you add it before HTTPS is stable, users may be locked out."
        ),
        code=None,
    ))
    steps.append(RemediationStep(
        title="Verify",
        description="Check the header is present and the max-age is at least 1 year.",
        code='curl -sI https://yourdomain.com | grep -i strict-transport-security',
        language="bash",
    ))
    return RemediationGuide(
        fix_type="missing_hsts",
        title="Missing HSTS Header",
        why_risky=(
            "Without HSTS, browsers may accept plain HTTP connections, making your users "
            "vulnerable to protocol-downgrade and man-in-the-middle attacks."
        ),
        steps=steps,
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    )


def _guide_missing_x_frame(technologies: list[str]) -> RemediationGuide:
    nginx_code = 'add_header X-Frame-Options "SAMEORIGIN" always;'
    apache_code = 'Header always set X-Frame-Options "SAMEORIGIN"'
    steps = _nginx_or_apache(technologies, nginx_code, apache_code)
    steps.append(RemediationStep(
        title="Verify",
        description="Confirm the header is returned by your server.",
        code='curl -sI https://yourdomain.com | grep -i x-frame-options',
        language="bash",
    ))
    return RemediationGuide(
        fix_type="missing_x_frame",
        title="Missing X-Frame-Options Header",
        why_risky=(
            "Without X-Frame-Options, attackers can embed your site in an iframe "
            "and trick users into clicking on hidden elements (clickjacking)."
        ),
        steps=steps,
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    )


def _guide_missing_x_content(technologies: list[str]) -> RemediationGuide:
    nginx_code = 'add_header X-Content-Type-Options "nosniff" always;'
    apache_code = 'Header always set X-Content-Type-Options "nosniff"'
    steps = _nginx_or_apache(technologies, nginx_code, apache_code)
    steps.append(RemediationStep(
        title="Verify",
        description="Check the header is present in the response.",
        code='curl -sI https://yourdomain.com | grep -i x-content-type-options',
        language="bash",
    ))
    return RemediationGuide(
        fix_type="missing_x_content",
        title="Missing X-Content-Type-Options Header",
        why_risky=(
            "Without this header, browsers may MIME-sniff responses and execute "
            "files as a different type than declared — enabling script injection attacks."
        ),
        steps=steps,
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    )


def _guide_http_without_https(technologies: list[str]) -> RemediationGuide:
    nginx_code = (
        "server {\n"
        "    listen 80;\n"
        "    server_name yourdomain.com www.yourdomain.com;\n"
        "    return 301 https://$host$request_uri;\n"
        "}"
    )
    apache_code = (
        "RewriteEngine On\n"
        "RewriteCond %{HTTPS} off\n"
        "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
    )
    return RemediationGuide(
        fix_type="http_without_https",
        title="HTTP Without HTTPS",
        why_risky=(
            "Your site is accessible over plain HTTP. Traffic between users and your server "
            "is unencrypted and can be intercepted or modified by attackers."
        ),
        steps=[
            RemediationStep(
                title="Get a TLS certificate",
                description=(
                    "Use Let's Encrypt (free) to obtain a certificate. "
                    "Run the certbot command below on your server."
                ),
                code="sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com",
                language="bash",
            ),
            RemediationStep(
                title="Redirect HTTP → HTTPS in Nginx",
                description="Add a redirect block so all HTTP traffic is sent to HTTPS automatically.",
                code=nginx_code,
                language="nginx",
            ),
            RemediationStep(
                title="Or redirect in Apache (.htaccess)",
                description="Add these lines to your `.htaccess` file.",
                code=apache_code,
                language="apache",
            ),
            RemediationStep(
                title="Verify the redirect",
                description="Confirm that HTTP redirects to HTTPS with a 301.",
                code="curl -sI http://yourdomain.com | grep -i location",
                language="bash",
            ),
        ],
        references=[
            "https://letsencrypt.org/getting-started/",
            "https://nginx.org/en/docs/http/configuring_https_servers.html",
        ],
    )


def _guide_expired_tls(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="expired_tls",
        title="Expired TLS Certificate",
        why_risky=(
            "Your TLS certificate has expired. Browsers will show a full-screen security "
            "warning to every visitor, and encrypted connections may be rejected entirely."
        ),
        steps=[
            RemediationStep(
                title="Renew with Certbot (Let's Encrypt)",
                description="Run this command on your server. Certbot will renew and reload automatically.",
                code="sudo certbot renew --force-renewal\nsudo systemctl reload nginx",
                language="bash",
            ),
            RemediationStep(
                title="Set up auto-renewal (recommended)",
                description="Add a cron job so the certificate renews before it expires.",
                code="# Check twice daily (standard Let's Encrypt recommendation)\n0 0,12 * * * root certbot renew --quiet",
                language="bash",
            ),
            RemediationStep(
                title="Verify the new expiry date",
                description="Confirm the certificate is valid and shows the correct expiry.",
                code="echo | openssl s_client -connect yourdomain.com:443 2>/dev/null \\\n  | openssl x509 -noout -dates",
                language="bash",
            ),
        ],
        references=["https://certbot.eff.org/docs/using.html#renewing-certificates"],
    )


def _guide_weak_tls(technologies: list[str], tls_version: str | None) -> RemediationGuide:
    detected = tls_version or "TLS 1.0 / 1.1"
    nginx_code = (
        "ssl_protocols TLSv1.2 TLSv1.3;\n"
        "ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "ssl_prefer_server_ciphers on;"
    )
    apache_code = (
        "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
        "SSLCipherSuite HIGH:!aNULL:!MD5\n"
        "SSLHonorCipherOrder on"
    )
    return RemediationGuide(
        fix_type="weak_tls",
        title="Weak TLS Version",
        why_risky=(
            f"Your server is negotiating {detected}, which has known cryptographic weaknesses. "
            "Attackers can downgrade or decrypt connections using BEAST, POODLE, or similar attacks."
        ),
        steps=_nginx_or_apache(technologies, nginx_code, apache_code) + [
            RemediationStep(
                title="Reload your web server",
                description="Apply the config change without downtime.",
                code="sudo nginx -t && sudo systemctl reload nginx\n# or: sudo systemctl reload apache2",
                language="bash",
            ),
            RemediationStep(
                title="Test with SSL Labs",
                description="Verify your server now scores A or above.",
                code="# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com",
                language="bash",
            ),
        ],
        references=[
            "https://ssl-config.mozilla.org/",
            "https://www.ssllabs.com/ssltest/",
        ],
    )


def _guide_tls_missing_443(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="tls_missing_443",
        title="Port 443 Open Without TLS",
        why_risky=(
            "Port 443 is responding but the TLS handshake fails. "
            "Any sensitive data sent to this port is transmitted in plain text."
        ),
        steps=[
            RemediationStep(
                title="Obtain a TLS certificate",
                description="Use Let's Encrypt / Certbot to get a free certificate.",
                code="sudo certbot --nginx -d yourdomain.com",
                language="bash",
            ),
            RemediationStep(
                title="Configure Nginx to serve HTTPS on port 443",
                description="Add an SSL server block if one doesn't already exist.",
                code=(
                    "server {\n"
                    "    listen 443 ssl;\n"
                    "    server_name yourdomain.com;\n\n"
                    "    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;\n"
                    "    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;\n"
                    "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                    "}"
                ),
                language="nginx",
            ),
            RemediationStep(
                title="Verify the TLS handshake",
                description="Confirm that a valid TLS connection can now be established.",
                code="openssl s_client -connect yourdomain.com:443 -tls1_2",
                language="bash",
            ),
        ],
        references=["https://nginx.org/en/docs/http/configuring_https_servers.html"],
    )


def _guide_unexpected_port(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="unexpected_port",
        title="Unexpected Open Port",
        why_risky=(
            "An open port that isn't required for normal operation expands your attack surface. "
            "Attackers probe open ports to find exploitable services."
        ),
        steps=[
            RemediationStep(
                title="Identify the service using the port",
                description="Find which process is listening and decide if it's needed.",
                code="sudo ss -tlnp | grep <PORT>\nsudo lsof -i :<PORT>",
                language="bash",
            ),
            RemediationStep(
                title="Stop the service if not needed",
                description="Disable and stop the service so the port closes.",
                code="sudo systemctl stop <service-name>\nsudo systemctl disable <service-name>",
                language="bash",
            ),
            RemediationStep(
                title="Block with firewall (UFW)",
                description="Even if the service runs internally, block the port externally.",
                code="sudo ufw deny <PORT>/tcp\nsudo ufw reload",
                language="bash",
            ),
            RemediationStep(
                title="Or block with iptables",
                description="Alternative to UFW for iptables-based systems.",
                code=(
                    "sudo iptables -A INPUT -p tcp --dport <PORT> -j DROP\n"
                    "sudo iptables-save > /etc/iptables/rules.v4"
                ),
                language="bash",
            ),
        ],
        references=["https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands"],
    )


def _guide_risky_port(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="risky_port",
        title="Risky Port Exposed",
        why_risky=(
            "A port associated with a high-risk service (e.g. Telnet, FTP, RDP) is exposed "
            "to the internet. These services have known vulnerabilities and are actively targeted."
        ),
        steps=[
            RemediationStep(
                title="Identify the risky service",
                description="Check what is running on the flagged port.",
                code="sudo ss -tlnp | grep <PORT>",
                language="bash",
            ),
            RemediationStep(
                title="Replace insecure protocols",
                description=(
                    "Use SSH instead of Telnet, SFTP/SCP instead of FTP, "
                    "a VPN tunnel instead of exposing RDP directly."
                ),
                code=None,
            ),
            RemediationStep(
                title="Restrict access to trusted IPs only",
                description="If the service must stay running, whitelist only known IP ranges.",
                code=(
                    "# Allow only your office IP\n"
                    "sudo ufw allow from <YOUR_IP> to any port <PORT>\n"
                    "sudo ufw deny <PORT>"
                ),
                language="bash",
            ),
        ],
        references=[
            "https://www.cisa.gov/news-events/alerts/2019/10/09/top-routinely-exploited-vulnerabilities",
        ],
    )


def _guide_missing_spf(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="missing_spf",
        title="Missing SPF Record",
        why_risky=(
            "Without an SPF record, any server on the internet can send email claiming to be "
            "from your domain. This enables phishing and email spoofing attacks."
        ),
        steps=[
            RemediationStep(
                title="Add a TXT record in your DNS",
                description=(
                    "Log in to your DNS provider and add the following TXT record "
                    "at the root of your domain (@)."
                ),
                code='v=spf1 include:_spf.google.com ~all\n# Replace with your actual mail provider\'s SPF include',
                language="dns",
            ),
            RemediationStep(
                title="Verify the record propagated",
                description="Use dig or an online tool to confirm the SPF record is live.",
                code="dig TXT yourdomain.com | grep spf",
                language="bash",
            ),
        ],
        references=[
            "https://dmarcian.com/spf-syntax-table/",
            "https://mxtoolbox.com/spf.aspx",
        ],
    )


def _guide_weak_spf(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="weak_spf",
        title="Weak SPF Policy",
        why_risky=(
            "Your SPF record uses `+all` or `?all`, which allows any server to pass SPF checks. "
            "This makes SPF protection useless against email spoofing."
        ),
        steps=[
            RemediationStep(
                title="Change the SPF qualifier to ~all or -all",
                description=(
                    "`~all` (softfail) is recommended for most. "
                    "`-all` (hardfail) is strictest but may cause delivery issues if your sending IPs aren't all listed."
                ),
                code='# Recommended (softfail)\nv=spf1 include:_spf.yourprovider.com ~all\n\n# Strictest (hardfail)\nv=spf1 include:_spf.yourprovider.com -all',
                language="dns",
            ),
            RemediationStep(
                title="Verify the updated record",
                description="Confirm the new SPF record is visible via DNS lookup.",
                code="dig TXT yourdomain.com | grep spf",
                language="bash",
            ),
        ],
        references=["https://dmarcian.com/spf-syntax-table/"],
    )


def _guide_duplicate_spf(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="duplicate_spf",
        title="Duplicate SPF Record",
        why_risky=(
            "Having more than one SPF TXT record causes mail servers to fail SPF validation "
            "entirely, as the RFC requires exactly one. Your email may be rejected or spoofed."
        ),
        steps=[
            RemediationStep(
                title="List all existing SPF records",
                description="Identify which records exist so you can consolidate them.",
                code="dig TXT yourdomain.com | grep spf",
                language="bash",
            ),
            RemediationStep(
                title="Merge into a single SPF record",
                description=(
                    "Delete all but one SPF TXT record. "
                    "Combine all `include:` statements into one record."
                ),
                code='# Example: merging two records into one\nv=spf1 include:_spf.google.com include:sendgrid.net ~all',
                language="dns",
            ),
        ],
        references=["https://dmarcian.com/duplicate-spf-records/"],
    )


def _guide_missing_dmarc(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="missing_dmarc",
        title="Missing DMARC Record",
        why_risky=(
            "Without DMARC, even if SPF and DKIM are configured, there's no policy telling "
            "receiving servers what to do with mail that fails authentication. "
            "Attackers can still spoof your domain."
        ),
        steps=[
            RemediationStep(
                title="Add a DMARC TXT record",
                description=(
                    "Add this TXT record to `_dmarc.yourdomain.com` in your DNS. "
                    "Start with `p=none` to monitor before enforcing."
                ),
                code='v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com; ruf=mailto:dmarc-forensics@yourdomain.com; fo=1',
                language="dns",
            ),
            RemediationStep(
                title="Upgrade to enforcement once monitoring is clean",
                description=(
                    "After reviewing reports for 2–4 weeks and confirming legitimate mail passes, "
                    "change `p=none` to `p=quarantine`, then `p=reject`."
                ),
                code='v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com',
                language="dns",
            ),
            RemediationStep(
                title="Verify",
                description="Confirm the DMARC record is live.",
                code="dig TXT _dmarc.yourdomain.com",
                language="bash",
            ),
        ],
        references=[
            "https://dmarc.org/overview/",
            "https://dmarcian.com/dmarc-record-wizard/",
        ],
    )


def _guide_weak_dmarc(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="weak_dmarc",
        title="Weak DMARC Policy",
        why_risky=(
            "Your DMARC record uses `p=none`, which only monitors — it doesn't reject or "
            "quarantine spoofed emails. Attackers can still impersonate your domain."
        ),
        steps=[
            RemediationStep(
                title="Review your DMARC reports first",
                description=(
                    "Before tightening policy, verify all your legitimate sending sources "
                    "pass SPF/DKIM checks by reviewing aggregate reports."
                ),
                code="dig TXT _dmarc.yourdomain.com",
                language="bash",
            ),
            RemediationStep(
                title="Upgrade to p=quarantine or p=reject",
                description=(
                    "`p=quarantine` sends failing mail to spam. "
                    "`p=reject` blocks it outright. Use `pct=` to roll out gradually."
                ),
                code=(
                    "# Step 1: quarantine 10% of failing mail\n"
                    "v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc-reports@yourdomain.com\n\n"
                    "# Step 2: full rejection\n"
                    "v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com"
                ),
                language="dns",
            ),
        ],
        references=["https://dmarc.org/2016/01/dmarc-and-pct/"],
    )


def _guide_missing_dkim(_: list[str]) -> RemediationGuide:
    return RemediationGuide(
        fix_type="missing_dkim",
        title="Missing DKIM",
        why_risky=(
            "Without DKIM, emails from your domain cannot be cryptographically verified. "
            "This allows attackers to forge email headers and impersonate your organization."
        ),
        steps=[
            RemediationStep(
                title="Enable DKIM in your email provider",
                description=(
                    "Most providers (Google Workspace, Microsoft 365, SendGrid, etc.) "
                    "can generate and host a DKIM key for you. Enable it in your provider's admin panel."
                ),
                code=None,
            ),
            RemediationStep(
                title="Add the DKIM TXT record to your DNS",
                description=(
                    "Your provider will give you a TXT record to add at "
                    "`<selector>._domainkey.yourdomain.com`."
                ),
                code='# Example (Google Workspace)\n# Name:  google._domainkey.yourdomain.com\n# Value: v=DKIM1; k=rsa; p=<your-public-key>',
                language="dns",
            ),
            RemediationStep(
                title="Verify DKIM is working",
                description="Send a test email to mail-tester.com or use dig to check the record.",
                code="dig TXT google._domainkey.yourdomain.com",
                language="bash",
            ),
        ],
        references=[
            "https://dkim.org/",
            "https://mxtoolbox.com/dkim.aspx",
        ],
    )


# ── Public entry point ────────────────────────────────────────────────────────

_GUIDE_REGISTRY: dict[str, Any] = {
    # Application Security
    "missing_csp":       lambda tech, tls: _guide_missing_csp(tech),
    "missing_hsts":      lambda tech, tls: _guide_missing_hsts(tech),
    "missing_x_frame":   lambda tech, tls: _guide_missing_x_frame(tech),
    "missing_x_content": lambda tech, tls: _guide_missing_x_content(tech),
    "http_without_https":lambda tech, tls: _guide_http_without_https(tech),
    # TLS Security
    "expired_tls":       lambda tech, tls: _guide_expired_tls(tech),
    "weak_tls":          lambda tech, tls: _guide_weak_tls(tech, tls),
    "tls_missing_443":   lambda tech, tls: _guide_tls_missing_443(tech),
    # Network Security
    "unexpected_port":   lambda tech, tls: _guide_unexpected_port(tech),
    "risky_port":        lambda tech, tls: _guide_risky_port(tech),
    "port":              lambda tech, tls: _guide_unexpected_port(tech),
    # DNS / Email Security
    "missing_spf":       lambda tech, tls: _guide_missing_spf(tech),
    "weak_spf":          lambda tech, tls: _guide_weak_spf(tech),
    "duplicate_spf":     lambda tech, tls: _guide_duplicate_spf(tech),
    "missing_dmarc":     lambda tech, tls: _guide_missing_dmarc(tech),
    "weak_dmarc":        lambda tech, tls: _guide_weak_dmarc(tech),
    "missing_dkim":      lambda tech, tls: _guide_missing_dkim(tech),
}


def generate_remediation(
    fix_type: str,
    technologies: list[str] | None = None,
    tls_version: str | None = None,
    subdomain: str | None = None,   # ← add this
) -> dict:
    technologies = technologies or []
    domain_label = subdomain or "yourdomain.com"   # ← add this
    
    builder = _GUIDE_REGISTRY.get(fix_type)

    if not builder:
        return {
            "fix_type": fix_type,
            "title": "Unknown Issue",
            "why_risky": "No remediation guide is available for this issue type.",
            "steps": [],
            "references": [],
        }

    guide: RemediationGuide = builder(technologies, tls_version)
    result = guide.to_dict()

    # ── Replace all yourdomain.com placeholders with the actual subdomain ──
    import json
    raw = json.dumps(result)
    raw = raw.replace("yourdomain.com", domain_label)
    return json.loads(raw)
