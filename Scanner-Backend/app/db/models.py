import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Integer, Boolean, ForeignKey, TIMESTAMP, Index, DateTime, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import JSON
from sqlalchemy.sql import func
from app.db.base import Base
import enum


class InvitationStatus(str, enum.Enum):
    """Status for user invitations"""
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"


class Organization(Base):
    __tablename__ = "organizations"

    org_id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=False)
    domain = Column(JSON, nullable=True)
    max_domains = Column(Integer, default=1, nullable=False)

class User(Base):
    __tablename__ = "users"

    user_id                   = Column(String(36), primary_key=True)
    org_id                    = Column(String(36), ForeignKey("organizations.org_id"), nullable=True)
    email                     = Column(String(255), unique=True, nullable=False)
    password                  = Column(String(255), nullable=False)
    role                      = Column(String(20), nullable=False, default="owner")
    created_at                = Column(TIMESTAMP, server_default=func.now())
    email_verified            = Column(Boolean, nullable=False, server_default="true")
    failed_login_attempts     = Column(Integer, nullable=False, default=0)
    last_failed_login_at      = Column(TIMESTAMP, nullable=True)
    locked_until              = Column(TIMESTAMP, nullable=True)
    verification_token        = Column(String(255), unique=True, nullable=True)
    verification_expires_at   = Column(TIMESTAMP, nullable=True)
    pending_registration_domain = Column(Text, nullable=True)

    # ── NEW: TOTP columns ─────────────────────────────────────────────────────
    totp_secret     = Column(String(64), nullable=True)
    # NULL  → user has never set up Google Authenticator
    # value → the Base32 secret tied to their Authenticator app entry

    is_totp_enabled = Column(Boolean, nullable=False, server_default="false")
    # False → setup not yet confirmed (secret might exist but not verified)
    # True  → user successfully verified a code at least once; TOTP is active

class Invitation(Base):
    __tablename__ = "invitations"

    invite_id = Column(String(36), primary_key=True)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    email = Column(String(255), nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    invited_by = Column(String(36), ForeignKey("users.user_id"), nullable=False)
    expires_at = Column(TIMESTAMP, nullable=False)


class PersonalEmailInvitation(Base):
    __tablename__ = "personal_email_invitations"

    invitation_id = Column(String(36), primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    approved_by = Column(String(36), ForeignKey("users.user_id"), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    approved_at = Column(TIMESTAMP, nullable=True)
    expires_at = Column(TIMESTAMP, nullable=True)
    notes = Column(Text, nullable=True)


class PublicReportRequest(Base):
    __tablename__ = "public_report_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, index=True)
    domain = Column(Text, nullable=False, index=True)
    report_payload = Column(JSON, nullable=False, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_public_report_requests_created", "created_at"),
    )


class PasswordResetOTP(Base):
    __tablename__ = "password_reset_otps"

    user_id = Column(String(36), ForeignKey("users.user_id"), primary_key=True)
    otp_hash = Column(String(255), nullable=False)
    expires_at = Column(TIMESTAMP, nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())

class PromoCode(Base):
    __tablename__ = "promo_codes"

    code_id = Column(String(36), primary_key=True)
    code = Column(String(50), unique=True, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    used_at = Column(TIMESTAMP, nullable=True)
    used_by = Column(String(36), ForeignKey("users.user_id"), nullable=True)
    expires_at = Column(TIMESTAMP, nullable=True)
    privilege_revoked = Column(Boolean, default=False, nullable=False)


class SubscriptionPlan(Base):
    __tablename__ = "subscription_plans"

    plan_id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    price = Column(Integer, nullable=False, default=0)
    icon = Column(String(255), nullable=True)
    color = Column(String(255), nullable=True)
    container_color = Column(String(255), nullable=True)
    popular = Column(Boolean, nullable=False, server_default="false")
    features = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)

class Blacklist(Base):
    __tablename__ = "blacklist"

    email = Column(String(255), primary_key=True)
    blocked_by = Column(String(36), ForeignKey("users.user_id"), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    admin_id = Column(String(36), ForeignKey("users.user_id"), nullable=True)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    public_ip = Column(String(45), nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    severity = Column(String(20), nullable=False, default="medium")
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)


class UserAssessment(Base):
    __tablename__ = "user_assessments"

    user_id = Column(String(36), ForeignKey("users.user_id"), primary_key=True)
    authentication = Column(JSON, nullable=True)
    web_browsing = Column(JSON, nullable=True)
    emails = Column(JSON, nullable=True)
    messaging = Column(JSON, nullable=True)
    social_media = Column(JSON, nullable=True)
    networks = Column(JSON, nullable=True)
    mobile_devices = Column(JSON, nullable=True)
    personal_computers = Column(JSON, nullable=True)
    smart_home = Column(JSON, nullable=True)
    personal_finance = Column(JSON, nullable=True)
    human_aspect = Column(JSON, nullable=True)
    physical_security = Column(JSON, nullable=True)


class ScanSummary(Base):
    __tablename__ = "scan_summary"

    domain = Column(Text, primary_key=True)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    domain_score = Column(Integer)
    weighted_score = Column(Float, nullable=True)  # Weighted score (0-100)
    base_score = Column(Float, nullable=True)  # Score before criticality adjustment
    domain_criticality = Column(String(20), nullable=False, default="medium")  # critical, high, medium, low
    severity = Column(String)
    mail_security = Column(JSON, nullable=True)
    app_security = Column(JSON, nullable=True)
    network_security = Column(JSON, nullable=True)
    tls_security = Column(JSON, nullable=True)
    dns_security = Column(JSON, nullable=True)
    ips = Column(JSON, nullable=True)
    scoring_breakdown = Column(JSON, nullable=True)  # Detailed scoring breakdown
    compliance_scores = Column(JSON, nullable=True)  # PCI-DSS, SOC2, GDPR scores

    __table_args__ = (
        Index("idx_scan_summary_score", "domain_score"),
        Index("idx_scan_summary_weighted", "weighted_score"),
        Index("idx_scan_summary_criticality", "domain_criticality"),
    )


class ScanScoreHistory(Base):
    __tablename__ = "scan_score_history"

    _id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    domain = Column(Text, nullable=False)
    domain_score = Column(Integer, nullable=False)
    result = Column(JSON, nullable=True)
    scan_date = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class MalwareScanResult(Base):
    __tablename__ = "malware_scan_results"

    scan_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    domain = Column(Text, nullable=False)
    result = Column(JSON, nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_malware_scan_org_domain", "org_id", "domain"),
        Index("idx_malware_scan_org_created", "org_id", "created_at"),
    )

class ActiveScan(Base):
    __tablename__ = "active_scan"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(Text, nullable=False)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    status = Column(String(50), nullable=False, default="pending")
    created_at = Column(TIMESTAMP, server_default=func.now())


class PortFixRequest(Base):
    __tablename__ = "port_fix_requests"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(255), nullable=False)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=True)
    domain = Column(Text, ForeignKey("scan_summary.domain"), nullable=False)
    host = Column(String(255), nullable=False)
    port_number = Column(Integer, nullable=False)
    service = Column(String(255), nullable=True)
    fix_type = Column(String(50), nullable=False, default="port")
    status = Column(String(50), nullable=False, default="pending")
    is_open = Column(Boolean, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    verification_scan_time = Column(TIMESTAMP, nullable=True)
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("idx_portfix_scan", "scan_id"),
        Index("idx_portfix_org", "org_id"),
        Index("idx_portfix_domain", "domain"),
        Index("idx_portfix_status", "status"),
    )


class FixStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class HeaderFixRequest(Base):
    __tablename__ = "header_fix_requests"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(255), nullable=False, unique=True)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=True)
    domain = Column(Text, ForeignKey("scan_summary.domain"), nullable=False)
    fix_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, default="pending")
    header_present = Column(Boolean, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    verification_scan_time = Column(TIMESTAMP, nullable=True)
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("idx_headerfix_scan", "scan_id"),
        Index("idx_headerfix_org", "org_id"),
        Index("idx_headerfix_domain", "domain"),
        Index("idx_headerfix_status", "status"),
    )


class TlsFixRequest(Base):
    __tablename__ = "tls_fix_requests"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(255), nullable=False, unique=True)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=True)
    domain = Column(Text, ForeignKey("scan_summary.domain"), nullable=False)
    fix_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, default="pending")
    tls_ok = Column(Boolean, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    verification_scan_time = Column(TIMESTAMP, nullable=True)
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("idx_tlsfix_scan", "scan_id"),
        Index("idx_tlsfix_org", "org_id"),
        Index("idx_tlsfix_domain", "domain"),
        Index("idx_tlsfix_status", "status"),
    )


class ResolvedFinding(Base):
    __tablename__ = "resolved_findings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    domain = Column(Text, ForeignKey("scan_summary.domain"), nullable=False)
    rule = Column(String(255), nullable=False)
    subdomain = Column(String(255), nullable=False)
    fix_type = Column(String(50), nullable=False)
    category = Column(String(100), nullable=False)
    resolved_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_resolved_org", "org_id"),
        Index("idx_resolved_domain", "domain"),
    )
class VaptImport(Base):
    """A normalized VAPT (Vulnerability Assessment & Penetration Testing) report
    imported from a Nessus / CSV / XLSX export file.

    The full normalized report (findings, aggregate summaries) is stored as JSON
    so the raw payload never needs to be re-parsed.
    """

    __tablename__ = "vapt_imports"

    import_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_format = Column(String(20), nullable=False, default="xml")  # xml | csv | xlsx
    source_tool = Column(String(50), nullable=False, default="generic")  # nessus | openvas | qualys | generic
    # Kept for compatibility with tables created by earlier schema versions
    # (which shipped a NOT NULL `status` column). Imports are stored fully
    # normalized, so the value is always "completed" at insert time.
    status = Column(String(20), nullable=False, default="completed", server_default="'completed'")
    total_findings = Column(Integer, nullable=False, default=0)
    unique_hosts = Column(Integer, nullable=False, default=0)
    risk_score = Column(Integer, nullable=False, default=0)  # 0-100 risk index
    severity = Column(String(20), nullable=False, default="none")
    severity_distribution = Column(JSON, nullable=True)
    category_distribution = Column(JSON, nullable=True)
    summary = Column(JSON, nullable=True)  # also carries excluded_info_findings + raw_findings_parsed
    findings = Column(JSON, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_vapt_org_created", "org_id", "created_at"),
    )


class ReportedIssue(Base):
    __tablename__ = "reported_issues"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(String(36), ForeignKey("organizations.org_id"), nullable=True)
    domain = Column(Text, nullable=False)
    subdomain = Column(String(255), nullable=True)
    rule = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=True)
    issue_type = Column(String(100), nullable=False)
    message = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="open")
    ref_id = Column(String(20), unique=True, nullable=False)
    reported_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    reviewed_at = Column(TIMESTAMP, nullable=True)
    reviewed_by = Column(String(36), ForeignKey("users.user_id"), nullable=True)
    admin_note = Column(Text, nullable=True)
    # ── Admin Review workflow (issue state machine) ──────────────────────────
    resolution = Column(String(50), nullable=True)   # scanner_correct | user_correct | false_positive | not_applicable
    resolved_at = Column(TIMESTAMP, nullable=True)
    evidence = Column(JSON, nullable=True)           # [{note, uploaded_by, uploaded_at}]
    verifications = Column(JSON, nullable=True)      # [{type, result, verified_by, verified_at}] (audit trail)

    __table_args__ = (
        Index("idx_reportedissue_org", "org_id"),
        Index("idx_reportedissue_domain", "domain"),
        Index("idx_reportedissue_status", "status"),
        Index("idx_reportedissue_ref", "ref_id"),
    )