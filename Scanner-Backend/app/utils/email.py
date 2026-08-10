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
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be configured to send VAPT rescan schedule emails.")

    import_link = f"{FRONTEND_URL.rstrip('/')}/admin/vapt-reports/{import_id}" if FRONTEND_URL else ""
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
            .btn {{ display: inline-block; background: linear-gradient(135deg, #0f3460, #533483); color: #fff !important; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; margin: 20px 0; }}
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
                <p>You can review the import and rescan details here:</p>
                <p style="text-align: center;"><a href="{import_link}" class="btn">View VAPT report</a></p>
                <p style="font-size: 13px; color: #888;">If the button does not work, copy and paste this link into your browser:<br/><a href="{import_link}" style="color: #0f3460; word-break: break-all;">{import_link}</a></p>
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
        f"Scheduled at: {scheduled_at_iso}. Hosts: {hosts_text}. "
        f"View import: {import_link}"
    )
    part1 = MIMEText(plain_text, "plain")
    part2 = MIMEText(html_content, "html")
    msg.attach(part1)
    msg.attach(part2)

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
