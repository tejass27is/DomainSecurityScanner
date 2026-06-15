import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
FRONTEND_URL = os.getenv("FRONTEND_URL")


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
    msg["From"] = f"Domain Scanner <{SMTP_USER}>"
    msg["To"] = to_email

    part1 = MIMEText(f"You've been invited by {sender_email} to join Domain Scanner. Email: {to_email}, Password: {plain_password}. Link: {login_link}", "plain")
    part2 = MIMEText(html_content, "html")

    msg.attach(part1)
    msg.attach(part2)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
    finally:
        server.quit()
    
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
    msg["From"] = f"Domain Scanner <{SMTP_USER}>"
    msg["To"] = to_email

    part1 = MIMEText(f"Your personal-email signup invitation is ready. Continue here: {invite_link}", "plain")
    part2 = MIMEText(html_content, "html")
    msg.attach(part1)
    msg.attach(part2)

    server = None
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
    finally:
        if server:
            server.quit()

    return True


def send_new_admin_credentials_email(to_email: str, plain_password: str, invited_by_email: str):
    if not FRONTEND_URL:
        raise ValueError("FRONTEND_URL must be set to send admin welcome emails.")

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
                <h1>Domain Scanner — Admin access</h1>
            </div>
            <div class="body">
                <p>Hello,</p>
                <p><strong>{invited_by_email}</strong> has created an administrator account for you on Domain Scanner.</p>
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
    msg["Subject"] = "Your Domain Scanner administrator account"
    msg["From"] = f"Domain Scanner <{SMTP_USER}>"
    msg["To"] = to_email

    part1 = MIMEText(
        f"You have been granted admin access on Domain Scanner by {invited_by_email}. "
        f"Email: {to_email}  Password: {plain_password}  Sign in: {login_link}",
        "plain",
    )
    part2 = MIMEText(html_content, "html")
    msg.attach(part1)
    msg.attach(part2)

    server = None
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
    finally:
        if server:
            server.quit()

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
    msg["From"] = f"Domain Scanner <{SMTP_USER}>"
    msg["To"] = to_email

    plain = f"Verify your Domain Scanner account by opening this link: {verify_url}"
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    server = None
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
    finally:
        if server:
            server.quit()

    return True


def send_login_otp_email(to_email: str, otp: str):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Domain Scanner login OTP"
    msg["From"] = f"Domain Scanner <{SMTP_USER}>"
    msg["To"] = to_email

    plain_text = f"Your Domain Scanner login OTP is {otp}. It expires in 10 minutes."
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; color: #222;">
        <p>Your one-time login password for Domain Scanner is:</p>
        <p style="font-size: 28px; font-weight: 700; letter-spacing: 2px;">{otp}</p>
        <p>This OTP expires in 10 minutes.</p>
        <p>If you did not try to sign in, you can ignore this email.</p>
    </body>
    </html>
    """

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    server = None
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
    finally:
        if server:
            server.quit()

    return True


def send_password_reset_otp_email(to_email: str, otp: str):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER and SMTP_PASSWORD must be strictly configured in .env to dispatch emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Domain Scanner password reset OTP"
    msg["From"] = f"Domain Scanner <{SMTP_USER}>"
    msg["To"] = to_email

    plain_text = f"Your Domain Scanner OTP is {otp}. It expires in 10 minutes."
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; color: #222;">
        <p>Your one-time password for Domain Scanner is:</p>
        <p style="font-size: 28px; font-weight: 700; letter-spacing: 2px;">{otp}</p>
        <p>This OTP expires in 10 minutes.</p>
        <p>If you did not request a password reset, you can ignore this email.</p>
    </body>
    </html>
    """

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    server = None
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
    finally:
        if server:
            server.quit()

    return True
