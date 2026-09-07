import os
import smtplib
import ssl
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_SERVER = os.getenv("SMTP_SERVER")
# Parse SMTP_PORT safely; default to 0 when not provided to avoid import-time errors.
try:
    SMTP_PORT = int(os.getenv("SMTP_PORT") or "0")
except (TypeError, ValueError):
    SMTP_PORT = 0
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
FRONTEND_URL = os.getenv("FRONTEND_URL")

# How long to wait for the SMTP server before failing (seconds).
SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS") or 20)
# Brand shown in the From address, email subjects and bodies.
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME") or "Domain Scanner"
# Lifetime of OTP codes (shown in OTP emails; must match the backend policy).
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES") or 10)


def _smtp_send(msg: MIMEMultipart) -> None:
    """Deliver an email via the configured SMTP server.

    Port 465 uses implicit TLS (SMTP_SSL); all other ports use STARTTLS.
    Fails fast with a clear error when SMTP is not configured, so callers
    can surface exactly what is wrong.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    if not SMTP_SERVER or not SMTP_PORT:
        raise ValueError("SMTP_SERVER and SMTP_PORT must be strictly configured in .env to dispatch emails.")

    server = None
    try:
        context = ssl.create_default_context()
        # Use implicit TLS for port 465, otherwise use STARTTLS with a secure context.
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS, context=context)
            server.ehlo()
        else:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS)
            server.ehlo()
            # Upgrade to TLS
            server.starttls(context=context)
            server.ehlo()

        server.login(SMTP_USER, SMTP_PASSWORD)

        msg["From"] = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
        # Templates hardcode the default brand name; swap in the configured one
        # across headers, subjects and bodies in one pass.
        raw_message = msg.as_string().replace("Domain Scanner", EMAIL_FROM_NAME)

        # Support multiple recipients in the To header (comma-separated)
        to_field = msg.get("To", "") or ""
        to_addrs = [addr.strip() for addr in to_field.split(",") if addr.strip()]

        # Prefer send_message where available to preserve headers, but fall back
        # to sendmail for older servers. Use envelope sender as SMTP_USER.
        try:
            if to_addrs:
                server.send_message(msg, from_addr=SMTP_USER, to_addrs=to_addrs)
            else:
                server.sendmail(SMTP_USER, msg.get("To"), raw_message)
        except Exception as send_err:
            # Normalize error for callers
            raise OSError(f"SMTP send failed: {send_err}")
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


def send_invite_email(to_email: str, plain_password: str, sender_email: str):

    login_link = f"{FRONTEND_URL}/login"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
            .container {{ max-width: 520px; margin: 0 auto; background: #fff; border-radius: 12px;
                          box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                       padding: 32px; text-align: center; }}
            .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
            .body {{ padding: 32px; color: #333; line-height: 1.6; }}
            .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483);
                    color: #fff !important; text-decoration: none; padding: 14px 32px;
                    border-radius: 8px; font-weight: 600; margin: 20px 0; }}
            .credentials {{ background: #f8f9fa; border-radius: 8px; padding: 16px; margin: 16px 0;
                            border-left: 4px solid #0f3460; }}
            .credentials p {{ margin: 4px 0; font-size: 14px; }}
            .credentials strong {{ color: #1a1a2e; }}
            .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px;
                       text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Domain Scanner</h1>
            </div>
            <div class="body">
                <p>Hello,</p>
                <p>You've been invited by <strong>{sender_email}</strong> to join Domain Scanner.</p>
                <p>Your account has been created. Here are your login credentials:</p>
                <div class="credentials">
                    <p><strong>Email:</strong> {to_email}</p>
                    <p><strong>Password:</strong> {plain_password}</p>
                </div>
                <p>Click the button below to get started:</p>
                <p style="text-align: center;">
                    <a href="{login_link}" class="btn">Go to Domain Scanner</a>
                </p>
                <p style="color: #e74c3c; font-size: 13px;">
                    ⚠️ Please change your password after your first login.
                </p>
                <p style="font-size: 13px; color: #888;">
                    If the button doesn't work, copy and paste this link into your browser:<br/>
                    <a href="{login_link}" style="color: #0f3460; word-break: break-all;">{login_link}</a>
                </p>
            </div>
            <div class="footer">
                &copy; Domain Scanner &mdash; Secure your digital presence.
            </div>
        </div>
    </body>
    </html>
    """

    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Invitation from {sender_email} to join Domain Scanner"
    msg["To"] = to_email

    part1 = MIMEText(f"You've been invited by {sender_email} to join Domain Scanner. Email: {to_email}, Password: {plain_password}. Link: {login_link}", "plain")
    part2 = MIMEText(html_content, "html")

    msg.attach(part1)
    msg.attach(part2)

    _smtp_send(msg)

    return True


def send_personal_email_invitation_email(to_email: str, invite_link: str, invited_by_email: str):
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be set to send personal email invitation emails.")

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
            .container {{ max-width: 560px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 32px; text-align: center; }}
            .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
            .body {{ padding: 32px; color: #333; line-height: 1.6; }}
            .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483); color: #fff !important; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; margin: 20px 0; }}
            .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h1>Domain Scanner — Personal Email Access</h1></div>
            <div class="body">
                <p>Hello,</p>
                <p><strong>{invited_by_email}</strong> has approved personal-email access for you on Domain Scanner.</p>
                <p>Use the button below to continue your signup with the approved invitation token.</p>
                <p style="text-align: center;"><a href="{invite_link}" class="btn">Continue signup</a></p>
                <p style="font-size: 13px; color: #888;">If the button does not work, copy and paste this link into your browser:<br/><a href="{invite_link}" style="color: #0f3460; word-break: break-all;">{invite_link}</a></p>
            </div>
            <div class="footer">&copy; Domain Scanner</div>
        </div>
    </body>
    </html>
    """

    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your approved Domain Scanner signup invitation"
    msg["To"] = to_email

    part1 = MIMEText(f"Your personal-email signup invitation is ready. Continue here: {invite_link}", "plain")
    part2 = MIMEText(html_content, "html")
    msg.attach(part1)
    msg.attach(part2)

    _smtp_send(msg)

    return True


def send_new_admin_credentials_email(to_email: str, plain_password: str, invited_by_email: str, role_label: str = "administrator"):
    """Send provisioned-account credentials (admin, SOC analyst, ...) by email."""
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be set to send account welcome emails.")

    login_link = f"{FRONTEND_URL.rstrip('/')}/auth"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
            .container {{ max-width: 520px; margin: 0 auto; background: #fff; border-radius: 12px;
                          box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                       padding: 32px; text-align: center; }}
            .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
            .body {{ padding: 32px; color: #333; line-height: 1.6; }}
            .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483);
                    color: #fff !important; text-decoration: none; padding: 14px 32px;
                    border-radius: 8px; font-weight: 600; margin: 20px 0; }}
            .credentials {{ background: #f8f9fa; border-radius: 8px; padding: 16px; margin: 16px 0;
                            border-left: 4px solid #0f3460; }}
            .credentials p {{ margin: 4px 0; font-size: 14px; }}
            .credentials strong {{ color: #1a1a2e; }}
            .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px;
                       text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Domain Scanner — {role_label} access</h1>
            </div>
            <div class="body">
                <p>Hello,</p>
                <p><strong>{invited_by_email}</strong> has created your {role_label} account on Domain Scanner.</p>
                <p>Use the credentials below to sign in:</p>
                <div class="credentials">
                    <p><strong>Email:</strong> {to_email}</p>
                    <p><strong>Password:</strong> {plain_password}</p>
                </div>
                <p style="text-align: center;">
                    <a href="{login_link}" class="btn">Sign in to Domain Scanner</a>
                </p>
                <p style="color: #e74c3c; font-size: 13px;">
                    Please change your password after your first login.
                </p>
                <p style="font-size: 13px; color: #888;">
                    If the button does not work, copy and paste this link into your browser:<br/>
                    <a href="{login_link}" style="color: #0f3460; word-break: break-all;">{login_link}</a>
                </p>
            </div>
            <div class="footer">
                &copy; Domain Scanner &mdash; Secure your digital presence.
            </div>
        </div>
    </body>
    </html>
    """

    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your Domain Scanner {role_label} account"
    msg["To"] = to_email

    part1 = MIMEText(
        f"You have been granted {role_label} access on Domain Scanner by {invited_by_email}. "
        f"Email: {to_email}  Password: {plain_password}  Sign in: {login_link}",
        "plain",
    )
    part2 = MIMEText(html_content, "html")
    msg.attach(part1)
    msg.attach(part2)

    _smtp_send(msg)

    return True


def send_scan_report_email(to_email: str, domain: str, pdf_bytes: bytes):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart()
    msg["Subject"] = f"Your Domain Scanner report for {domain}"
    msg["To"] = to_email

    msg.attach(MIMEText(f"Hello,\n\nYour requested security scan report for {domain} is attached below.\n\nRegards,\niSecurify", "plain"))

    attachment_name = f"{domain}-scan-report.pdf"
    pdf_part = MIMEApplication(pdf_bytes, Name=attachment_name)
    pdf_part["Content-Disposition"] = 'attachment; filename="%s"' % attachment_name
    msg.attach(pdf_part)

    _smtp_send(msg)

    return True


def send_vapt_rescan_schedule_email(
    to_email: str,
    scheduled_by_email: str,
    import_id: str,
    file_name: str,
    scheduled_at_iso: str,
    hosts: list[str],
    schedule_id: str,
):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    hosts_text = ", ".join(hosts) if hosts else "All hosts"

    subject = f"VAPT rescan scheduled for {file_name}"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
            .container {{ max-width: 560px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 32px; text-align: center; }}
            .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
            .body {{ padding: 32px; color: #333; line-height: 1.6; }}
            .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h1>VAPT Rescan Scheduled</h1></div>
            <div class="body">
                <p>Hello,</p>
                <p>A verification rescan was scheduled by <strong>{scheduled_by_email}</strong> for the VAPT import <strong>{file_name}</strong>.</p>
                <p><strong>Scheduled time:</strong> {scheduled_at_iso}</p>
                <p><strong>Hosts:</strong> {hosts_text}</p>
            </div>
            <div class="footer">&copy; Domain Scanner</div>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email

    plain_text = (
        f"A VAPT rescan was scheduled by {scheduled_by_email} for {file_name}. "
        f"Scheduled at: {scheduled_at_iso}. Hosts: {hosts_text}."
    )
    part1 = MIMEText(plain_text, "plain")
    part2 = MIMEText(html_content, "html")
    msg.attach(part1)
    msg.attach(part2)

    _smtp_send(msg)

    return True


_VAPT_EMAIL_HEADER = """<div style="background:#111827;padding:28px 32px;color:#fff"><div style="font-size:11px;letter-spacing:2.5px;text-transform:uppercase;color:#94a3b8;margin-bottom:8px">{email_brand}</div><h1 style="margin:0;font-size:22px;font-weight:700">{title}</h1></div>"""
_VAPT_EMAIL_FOOTER = """<div style="padding:18px 32px;background:#f9fafb;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:11px;text-align:center">This is an automated notification from {email_brand}.</div>"""


def _vapt_email_shell(title: str, body_html: str) -> str:
    """Wrap a body block in the standard VAPT email shell."""
    header = _VAPT_EMAIL_HEADER.format(email_brand=EMAIL_FROM_NAME, title=title)
    footer = _VAPT_EMAIL_FOOTER.format(email_brand=EMAIL_FROM_NAME)
    return (
        '<!doctype html><html><body '
        'style="margin:0;background:#f1f5f9;font-family:Segoe UI,Arial,sans-serif;'
        'color:#1e293b;line-height:1.6">'
        '<div style="max-width:580px;margin:36px auto;background:#fff;'
        'border:1px solid #e2e8f0;border-radius:12px;overflow:hidden">'
        + header
        + '<div style="padding:28px 32px">' + body_html + '</div>'
        + footer
        + '</div></body></html>'
    )


def send_vapt_access_event_email(
    to_email: str,
    event: str,
    org_name: str,
    region_code: str,
    region_name: str,
    note: str = "",
    testing_start_at: str = "",
    testing_end_at: str = "",
    testing_timezone: str = "",
):
    """Notify a client or SOC recipient about an initial/region VAPT decision."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    labels = {
        "access_request_submitted": "VAPT Access Request Received",
        "region_access_requested": "New Region Requested",
        "initial_access_approved": "VAPT Access Approved",
        "initial_access_rejected": "VAPT Access — Changes Requested",
        "checklist_approved": "VAPT Checklist Approved",
        "checklist_rejected": "VAPT Checklist — Changes Requested",
        "region_access_approved": "Region Access Approved",
        "region_access_rejected": "Region Access — Changes Requested",
        "initial_date_proposed": "Testing Date Proposed",
        "initial_date_accepted": "Testing Date Confirmed",
        "initial_date_rejected": "Testing Date — Changes Requested",
        "rescan_date_proposed": "Verification Scan Date Proposed",
        "rescan_date_rejected": "Verification Scan Date — Changes Requested",
    }
    title = labels.get(event, "VAPT Update")
    subject = title
    schedule = ""
    if testing_start_at or testing_end_at:
        schedule = f"\nTesting window: {testing_start_at} to {testing_end_at} ({testing_timezone or 'timezone not specified'})"
    plain = f"{title}\n\nOrganization: {org_name}\nRegion: {region_code} ({region_name}){schedule}\n\nRegards,\n{EMAIL_FROM_NAME}"
    # Build detail rows
    detail_rows = ""
    if org_name:
        detail_rows += f'<tr><td style="padding:9px 0;color:#64748b;font-size:13px;width:140px">Organization</td><td style="padding:9px 0;font-weight:600;font-size:13px">{org_name}</td></tr>'
    if region_code or region_name:
        region_display = f"{region_code} &middot; {region_name}" if region_code and region_name else (region_code or region_name)
        detail_rows += f'<tr><td style="padding:9px 0;color:#64748b;font-size:13px">Region</td><td style="padding:9px 0;font-weight:600;font-size:13px">{region_display}</td></tr>'
    if testing_start_at:
        tz_display = testing_timezone or "UTC"
        detail_rows += f'<tr><td style="padding:9px 0;color:#64748b;font-size:13px">Testing Start</td><td style="padding:9px 0;font-weight:600;font-size:13px">{testing_start_at} &nbsp;({tz_display})</td></tr>'
    if testing_end_at:
        detail_rows += f'<tr><td style="padding:9px 0;color:#64748b;font-size:13px">Testing End</td><td style="padding:9px 0;font-weight:600;font-size:13px">{testing_end_at}</td></tr>'
    details_table = f'<table style="width:100%;border-collapse:collapse;margin:16px 0 4px">{detail_rows}</table>' if detail_rows else ""
    note_block = ""
    if note and note.strip():
        note_block = f'<div style="margin:16px 0;padding:14px 16px;border-left:3px solid #6366f1;background:#f8fafc;border-radius:0 8px 8px 0;font-size:13px;color:#475569">{note.strip()}</div>'
    body_html = f"""
        <p style="font-size:14px;color:#334155;margin:0 0 16px">Hello,</p>
        <p style="font-size:14px;color:#334155;margin:0 0 20px">{title}.</p>
        {details_table}
        {note_block}
        <p style="font-size:13px;color:#64748b;margin:24px 0 0">Regards,<br><strong>{EMAIL_FROM_NAME}</strong></p>
    """
    html = _vapt_email_shell(title, body_html)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(msg)
    return True


def send_vapt_rescan_reminder_email(
    to_email: str,
    import_id: str,
    file_name: str,
    scheduled_at_iso: str,
):
    """Send the client a one-day-before verification scan reminder."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    subject = "Reminder: VAPT Verification Scan Tomorrow"
    plain_text = (
        f"This is a reminder that your verification scan for {file_name} "
        f"is scheduled for tomorrow at {scheduled_at_iso}."
    )
    body_html = f"""
        <p style="font-size:14px;color:#334155;margin:0 0 16px">Hello,</p>
        <p style="font-size:14px;color:#334155;margin:0 0 20px">This is a reminder that your verification scan is scheduled for tomorrow.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px;width:140px">Report</td><td style="padding:9px 0;font-weight:600;font-size:13px">{file_name}</td></tr>
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px">Scheduled Time</td><td style="padding:9px 0;font-weight:600;font-size:13px">{scheduled_at_iso}</td></tr>
        </table>
        <p style="font-size:13px;color:#64748b;margin:24px 0 0">Regards,<br><strong>{EMAIL_FROM_NAME}</strong></p>
    """
    html = _vapt_email_shell("Verification Scan Reminder", body_html)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(msg)
    return True


def send_vapt_cycle_closed_email(to_email: str, file_name: str, next_vapt_due_at: str):
    """Notify the client that SOC closed the cycle and set the next due date."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    subject = f"VAPT Cycle Closed: {file_name}"
    plain_text = f"SOC has closed the VAPT cycle for {file_name}. Your next VAPT assessment is due on {next_vapt_due_at}."
    body_html = f"""
        <p style="font-size:14px;color:#334155;margin:0 0 16px">Hello,</p>
        <p style="font-size:14px;color:#334155;margin:0 0 20px">SOC has reviewed and closed the VAPT cycle.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px;width:170px">Report</td><td style="padding:9px 0;font-weight:600;font-size:13px">{file_name}</td></tr>
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px">Next Assessment Due</td><td style="padding:9px 0;font-weight:600;font-size:13px">{next_vapt_due_at}</td></tr>
        </table>
        <p style="font-size:13px;color:#64748b;margin:24px 0 0">Regards,<br><strong>{EMAIL_FROM_NAME}</strong></p>
    """
    html = _vapt_email_shell("VAPT Cycle Closed", body_html)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(msg)
    return True


def send_vapt_verification_result_email(
    to_email: str,
    file_name: str,
    import_id: str,
    status: str,
    message: str = "",
):
    """Notify the client when SOC uploads a verification result."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured.")
    report_link = f"{FRONTEND_URL.rstrip('/')}/vapt/reports/{import_id}"
    subject = f"VAPT Verification: {file_name}"
    plain = f"Verification result: {status}\n\n{message or 'SOC uploaded a verification result.'}\n\nView report: {report_link}"
    msg_block = f'<div style="margin:16px 0;padding:14px 16px;border-left:3px solid #6366f1;background:#f8fafc;border-radius:0 8px 8px 0;font-size:13px;color:#475569">{message.strip()}</div>' if message and message.strip() else ""
    body_html = f"""
        <p style="font-size:14px;color:#334155;margin:0 0 16px">Hello,</p>
        <p style="font-size:14px;color:#334155;margin:0 0 20px">A verification result has been uploaded.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px;width:140px">Report</td><td style="padding:9px 0;font-weight:600;font-size:13px">{file_name}</td></tr>
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px">Status</td><td style="padding:9px 0;font-weight:600;font-size:13px">{status}</td></tr>
        </table>
        {msg_block}
        <p style="margin:20px 0"><a href="{report_link}" style="display:inline-block;background:#111827;color:#fff;text-decoration:none;padding:10px 24px;border-radius:6px;font-size:13px;font-weight:600">View VAPT Report</a></p>
        <p style="font-size:13px;color:#64748b;margin:24px 0 0">Regards,<br><strong>{EMAIL_FROM_NAME}</strong></p>
    """
    html = _vapt_email_shell("Verification Result", body_html)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(msg)
    return True


def send_vapt_report_published_email(to_email: str, file_name: str, import_id: str):
    """Notify client users that a new VAPT report is available."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured.")
    report_link = f"{FRONTEND_URL.rstrip('/')}/vapt/reports/{import_id}"
    subject = f"New VAPT Report: {file_name}"
    plain = f"A new VAPT report is available: {file_name}\n\nView report: {report_link}"
    body_html = f"""
        <p style="font-size:14px;color:#334155;margin:0 0 16px">Hello,</p>
        <p style="font-size:14px;color:#334155;margin:0 0 20px">A new VAPT report has been published and is ready for your review.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px;width:140px">Report</td><td style="padding:9px 0;font-weight:600;font-size:13px">{file_name}</td></tr>
        </table>
        <p style="margin:20px 0"><a href="{report_link}" style="display:inline-block;background:#111827;color:#fff;text-decoration:none;padding:10px 24px;border-radius:6px;font-size:13px;font-weight:600">View VAPT Report</a></p>
        <p style="font-size:13px;color:#64748b;margin:24px 0 0">Regards,<br><strong>{EMAIL_FROM_NAME}</strong></p>
    """
    html = _vapt_email_shell("New VAPT Report", body_html)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(msg)
    return True


def send_vapt_cycle_reopened_email(to_email: str, file_name: str, import_id: str):
    """Notify the client that SOC reopened remediation after verification."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured.")
    report_link = f"{FRONTEND_URL.rstrip('/')}/vapt/reports/{import_id}"
    subject = f"VAPT Remediation Reopened: {file_name}"
    plain = f"SOC reopened remediation for {file_name}. Please continue fixing the remaining findings.\n\nView report: {report_link}"
    body_html = f"""
        <p style="font-size:14px;color:#334155;margin:0 0 16px">Hello,</p>
        <p style="font-size:14px;color:#334155;margin:0 0 20px">SOC has reopened remediation. Please continue fixing the remaining findings.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px;width:140px">Report</td><td style="padding:9px 0;font-weight:600;font-size:13px">{file_name}</td></tr>
        </table>
        <p style="margin:20px 0"><a href="{report_link}" style="display:inline-block;background:#111827;color:#fff;text-decoration:none;padding:10px 24px;border-radius:6px;font-size:13px;font-weight:600">View VAPT Report</a></p>
        <p style="font-size:13px;color:#64748b;margin:24px 0 0">Regards,<br><strong>{EMAIL_FROM_NAME}</strong></p>
    """
    html = _vapt_email_shell("Remediation Reopened", body_html)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(msg)
    return True


def send_registration_verification_email(to_email: str, verify_url: str):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
            .container {{ max-width: 520px; margin: 0 auto; background: #fff; border-radius: 12px;
                          box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                       padding: 32px; text-align: center; }}
            .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
            .body {{ padding: 32px; color: #333; line-height: 1.6; }}
            .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483);
                    color: #fff !important; text-decoration: none; padding: 14px 32px;
                    border-radius: 8px; font-weight: 600; margin: 20px 0; }}
            .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px;
                       text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Verify your email</h1>
            </div>
            <div class="body">
                <p>Hello,</p>
                <p>Thanks for signing up for Domain Scanner. Click the button below to verify your email and activate your account.</p>
                <p style="text-align: center;">
                    <a href="{verify_url}" class="btn">Verify email</a>
                </p>
                <p style="font-size: 13px; color: #888;">
                    If the button does not work, copy and paste this link into your browser:<br/>
                    <a href="{verify_url}" style="color: #0f3460; word-break: break-all;">{verify_url}</a>
                </p>
                <p style="font-size: 13px; color: #888;">If you did not create an account, you can ignore this email.</p>
            </div>
            <div class="footer">
                &copy; Domain Scanner &mdash; Secure your digital presence.
            </div>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Verify your email — Domain Scanner"
    msg["To"] = to_email

    plain = f"Verify your Domain Scanner account by opening this link: {verify_url}"
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    _smtp_send(msg)

    return True


def send_login_otp_email(to_email: str, otp: str):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Domain Scanner login OTP"
    msg["To"] = to_email

    plain_text = f"Your Domain Scanner login OTP is {otp}. It expires in {OTP_EXPIRY_MINUTES} minutes."
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; color: #222;">
        <p>Your one-time login password for Domain Scanner is:</p>
        <p style="font-size: 28px; font-weight: 700; letter-spacing: 2px;">{otp}</p>
        <p>This OTP expires in {OTP_EXPIRY_MINUTES} minutes.</p>
        <p>If you did not try to sign in, you can ignore this email.</p>
    </body>
    </html>
    """

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    _smtp_send(msg)

    return True


def send_password_reset_otp_email(to_email: str, otp: str):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Domain Scanner password reset OTP"
    msg["To"] = to_email

    plain_text = f"Your Domain Scanner OTP is {otp}. It expires in {OTP_EXPIRY_MINUTES} minutes."
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; color: #222;">
        <p>Your one-time password for Domain Scanner is:</p>
        <p style="font-size: 28px; font-weight: 700; letter-spacing: 2px;">{otp}</p>
        <p>This OTP expires in {OTP_EXPIRY_MINUTES} minutes.</p>
        <p>If you did not request a password reset, you can ignore this email.</p>
    </body>
    </html>
    """

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    _smtp_send(msg)

    return True


def send_account_locked_email(to_email: str, locked_until_iso: str, attempts: int, lockout_minutes: int):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Security alert: Your Domain Scanner account was locked"
    msg["To"] = to_email

    support_link = FRONTEND_URL.rstrip('/') if FRONTEND_URL else ""
    lock_date = locked_until_iso.split("T")[0] if "T" in locked_until_iso else locked_until_iso
    plain_text = (
        f"Your Domain Scanner account was locked due to repeated failed sign-in attempts.\n"
        f"Email: {to_email}\n"
        f"Attempts: {attempts}\n"
        f"Locked until (UTC): {lock_date}\n\n"
        f"If this wasn't you, please reset your password or contact support: {support_link}"
    )

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; color: #222;">
        <h2 style="color:#c0392b;">Security alert: Account temporarily locked</h2>
        <p>Your Domain Scanner account (<strong>{to_email}</strong>) was locked after <strong>{attempts}</strong> failed sign‑in attempts.</p>
        <p>The account will remain locked until <strong>{lock_date} UTC</strong> (approximately {lockout_minutes} minutes).</p>
        <p>If this wasn't you, please reset your password immediately or contact your administrator.</p>
        <p style="font-size:12px;color:#888;">If you did initiate these sign-in attempts, no further action is needed; the lock will expire automatically.</p>
    </body>
    </html>
    """

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    _smtp_send(msg)

    return True


def send_client_review_completed_email(
    to_email: str,
    org_id: str,
    file_name: str,
    solved_count: int,
    total_findings: int,
    import_id: str,
):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured.")
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured.")

    report_link = f"{FRONTEND_URL.rstrip('/')}/vapt/reports/{import_id}"
    subject = f"Client completed review: {file_name}"
    html_content = f"""
    <!DOCTYPE html><html><head><style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
        .container {{ max-width: 560px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 32px; text-align: center; }}
        .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
        .body {{ padding: 32px; color: #333; line-height: 1.6; }}
        .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483); color: #fff !important; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; margin: 20px 0; }}
        .stat {{ background: #f0fdf4; border-radius: 8px; padding: 16px; margin: 16px 0; border-left: 4px solid #16a34a; }}
        .stat strong {{ color: #16a34a; }}
        .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px; text-align: center; }}
    </style></head><body>
        <div class="container">
            <div class="header"><h1>VAPT Client Review Completed</h1></div>
            <div class="body">
                <p>Hello,</p>
                <p>The client completed their review of <strong>{file_name}</strong>.</p>
                <div class="stat"><p><strong>{solved_count}</strong> of <strong>{total_findings}</strong> findings confirmed resolved</p></div>
                <p style="text-align: center;"><a href="{report_link}" class="btn">View Report</a></p>
            </div>
            <div class="footer">&copy; Domain Scanner</div>
        </div>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    plain = f"Client completed review of {file_name}. {solved_count}/{total_findings} findings resolved. Report: {report_link}"
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_content, "html"))
    _smtp_send(msg)
    return True


def send_vapt_remediation_review_email(
    to_email: str,
    file_name: str,
    import_id: str,
    decision: str,
):
    """Notify the client when SOC accepts or rejects remediation."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured.")

    approved = decision == "approved"
    title = "Remediation Accepted" if approved else "More Remediation Required"
    message = (
        "Your remediation review was accepted. You can now schedule a verification scan."
        if approved
        else "SOC reviewed your remediation and requires additional fixes before verification."
    )
    report_link = f"{FRONTEND_URL.rstrip('/')}/vapt/reports/{import_id}"
    plain = f"{title}\n\n{message}\n\nView report: {report_link}"
    body_html = f"""
        <p style="font-size:14px;color:#334155;margin:0 0 16px">Hello,</p>
        <p style="font-size:14px;color:#334155;margin:0 0 20px">{message}</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px;width:140px">Report</td><td style="padding:9px 0;font-weight:600;font-size:13px">{file_name}</td></tr>
            <tr><td style="padding:9px 0;color:#64748b;font-size:13px">Status</td><td style="padding:9px 0;font-weight:600;font-size:13px">{"Approved" if approved else "Requires Fixes"}</td></tr>
        </table>
        <p style="margin:20px 0"><a href="{report_link}" style="display:inline-block;background:#111827;color:#fff;text-decoration:none;padding:10px 24px;border-radius:6px;font-size:13px;font-weight:600">View VAPT Report</a></p>
        <p style="font-size:13px;color:#64748b;margin:24px 0 0">Regards,<br><strong>{EMAIL_FROM_NAME}</strong></p>
    """
    html = _vapt_email_shell(title, body_html)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{title}: {file_name}"
    msg["To"] = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    _smtp_send(msg)
    return True


def send_remediation_followup_reminder_email(
    to_email: str,
    import_id: str,
    file_name: str,
    org_id: str,
    org_domain: str | None = None,
    since: str = "",
):
    """Notify SOC that a report has been in remediation_required for 7+ days
    with no logged support-contact, so follow-up is overdue."""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be configured.")
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured.")

    report_link = f"{FRONTEND_URL.rstrip('/')}/admin/vapt-reports/{import_id}"
    subject = f"Follow-up overdue: remediation support for {file_name}"
    plain_text = (
        f"The VAPT report '{file_name}' (org: {org_domain or org_id}) has been "
        f"in remediation_required since {since}. No support-offered action has "
        f"been logged. Please follow up with the client.\n\nView report: {report_link}"
    )
    html_content = f"""
    <!DOCTYPE html><html><head><style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
        .container {{ max-width: 560px; margin: 0 auto; background: #fff; border-radius: 12px;
                      box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); padding: 32px; text-align: center; }}
        .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
        .body {{ padding: 32px; color: #333; line-height: 1.6; }}
        .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483); color: #fff !important;
                text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; margin: 20px 0; }}
        .alert {{ background: #fef2f2; border-radius: 8px; padding: 16px; margin: 16px 0;
                  border-left: 4px solid #dc2626; color: #991b1b; }}
        .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px; text-align: center; }}
    </style></head><body>
        <div class="container">
            <div class="header"><h1>VAPT Remediation Follow-up Overdue</h1></div>
            <div class="body">
                <p>Hello,</p>
                <p>The VAPT report <strong>{file_name}</strong> for organisation
                   <strong>{org_domain or org_id}</strong> has been in
                   <strong>remediation_required</strong> since {since} with no
                   logged support-contact.</p>
                <div class="alert">
                    <p>Please follow up with the client by phone, email, or other
                       means, then use the <strong>Log support offered</strong>
                       action to reset the reminder timer.</p>
                </div>
                <p style="text-align: center;"><a href="{report_link}" class="btn">View Report</a></p>
            </div>
            <div class="footer">&copy; Domain Scanner</div>
        </div>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))
    _smtp_send(msg)
    return True


def send_rescan_failed_email(
    to_email: str,
    org_id: str,
    file_name: str,
    error_message: str,
    import_id: str,
):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured.")
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured.")

    report_link = f"{FRONTEND_URL.rstrip('/')}/admin/vapt-reports/{import_id}"
    subject = f"VAPT scan failed: {file_name}"
    html_content = f"""
    <!DOCTYPE html><html><head><style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; padding: 40px 0; }}
        .container {{ max-width: 560px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); padding: 32px; text-align: center; }}
        .header h1 {{ color: #fff; margin: 0; font-size: 22px; }}
        .body {{ padding: 32px; color: #333; line-height: 1.6; }}
        .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483); color: #fff !important; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; margin: 20px 0; }}
        .error {{ background: #fef2f2; border-radius: 8px; padding: 16px; margin: 16px 0; border-left: 4px solid #dc2626; color: #991b1b; }}
        .footer {{ padding: 20px 32px; background: #f8f9fa; color: #888; font-size: 12px; text-align: center; }}
    </style></head><body>
        <div class="container">
            <div class="header"><h1>VAPT Scan Failed</h1></div>
            <div class="body">
                <p>Hello,</p>
                <p>A verification scan for <strong>{file_name}</strong> has failed.</p>
                <div class="error"><p>Error: {error_message}</p></div>
                <p style="text-align: center;"><a href="{report_link}" class="btn">View Report</a></p>
            </div>
            <div class="footer">&copy; Domain Scanner</div>
        </div>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    plain = f"Scan failed for {file_name}. Error: {error_message}. Report: {report_link}"
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_content, "html"))
    _smtp_send(msg)
    return True
