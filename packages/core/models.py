"""Orvex data model.

Tenancy: every tenant-scoped table carries ``org_id`` and is protected by RLS (see
migrations). Idempotency: result tables have a natural unique key per scan so pipeline
stages can ``ON CONFLICT DO UPDATE`` and a re-run never duplicates rows.

Honesty invariant (enforced in code, not just docs): IDOR / broken-access-control /
business-logic findings are hard-capped at confidence=CANDIDATE. See
``Finding.__init__`` and ``CONFIRMABLE_TYPES``.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    return datetime.now(UTC)


def pg_enum(enum_cls, name: str):
    """A Postgres ENUM whose stored labels are the members' string VALUES (lowercase),
    not their Python names. Keeps DB labels aligned with the values used in app code and
    in CHECK constraints (e.g. 'confirmed', not 'CONFIRMED')."""
    return Enum(enum_cls, name=name, values_callable=lambda e: [m.value for m in e])


# --------------------------------------------------------------------------- enums
class Role(str, enum.Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Aggressiveness(str, enum.Enum):
    PASSIVE = "passive"
    SAFE = "safe"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


class StageStatus(str, enum.Enum):
    BLOCKED = "blocked"  # deps not yet met
    READY = "ready"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"  # disabled in config or gated off
    FAILED = "failed"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, enum.Enum):
    INFORMATIONAL = "informational"
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    REPORTED = "reported"
    RESOLVED = "resolved"


class AuthorizationType(str, enum.Enum):
    BUG_BOUNTY = "bug_bounty"
    PENTEST_SOW = "pentest_sow"
    INTERNAL = "internal"


class ScopeRuleKind(str, enum.Enum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"


class ScopeRuleAction(str, enum.Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


# Finding types that may EVER reach confidence=confirmed. Everything not here is capped
# at candidate. IDOR / access-control / business-logic are deliberately absent.
CONFIRMABLE_TYPES: frozenset[str] = frozenset(
    {
        "open_port",
        "tls_issue",
        "waf_present",
        "cdn_present",
        "exposed_secret_verified",
        "cve_active_confirmed",
        "missing_security_header",
        "cors_reflect_credentials",
        "open_redirect_canary",
        "ssrf_oast_callback",
        "user_enumeration",
        "bruteforce_protection_present",
        "default_credentials_accepted",
        # nuclei matcher-based detections (the template matched real response content, so the
        # presence is confirmed — this is the "reliably automatable" class from the spec).
        "exposure",
        "misconfiguration",
        "disclosure",
        "subdomain_takeover",
        "exposed_panel",
    }
)

# Types that must never be marked more confident than candidate.
CANDIDATE_CAPPED_TYPES: frozenset[str] = frozenset(
    {
        "idor",
        "broken_access_control",
        "business_logic",
        "injection_candidate",
        "sqli_candidate",
        "xss_candidate",
        "ssrf_candidate",
        "open_redirect_candidate",
    }
)


# --------------------------------------------------------------------------- mixins
class PKMixin:
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, server_default=func.now()
    )


class TenantMixin:
    """Adds org_id — the column RLS policies filter on."""

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )


# --------------------------------------------------------------------------- tenancy
class Organization(PKMixin, Base):
    __tablename__ = "organizations"
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)


class User(PKMixin, Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Membership(PKMixin, TenantMixin, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("org_id", "user_id", name="uq_membership_org_user"),)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[Role] = mapped_column(pg_enum(Role, "role"), nullable=False)


# --------------------------------------------------------------------------- program/authz
class Program(PKMixin, TenantMixin, Base):
    __tablename__ = "programs"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_program_org_slug"),)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    platform: Mapped[str | None] = mapped_column(String(80))  # hackerone/bugcrowd/private
    program_url: Mapped[str | None] = mapped_column(Text)
    scope_rules: Mapped[list[ScopeRule]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )
    authorizations: Mapped[list[Authorization]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )


class ScopeRule(PKMixin, TenantMixin, Base):
    __tablename__ = "scope_rules"
    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[ScopeRuleKind] = mapped_column(pg_enum(ScopeRuleKind, "scope_rule_kind"))
    action: Mapped[ScopeRuleAction] = mapped_column(pg_enum(ScopeRuleAction, "scope_rule_action"))
    value: Mapped[str] = mapped_column(String(400), nullable=False)  # stored normalised
    program: Mapped[Program] = relationship(back_populates="scope_rules")


class Authorization(PKMixin, TenantMixin, Base):
    """Required per program — no scan runs without a live one."""

    __tablename__ = "authorizations"
    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False
    )
    authorized_by: Mapped[str] = mapped_column(String(200), nullable=False)
    authorization_type: Mapped[AuthorizationType] = mapped_column(
        pg_enum(AuthorizationType, "authorization_type"), nullable=False
    )
    evidence_ref: Mapped[str | None] = mapped_column(Text)  # SoW link / scope snapshot ref
    # NOT NULL by policy: an authorization always has an expiry.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    allows_active_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allows_automated_tools: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    program_rate_cap_rps: Mapped[float | None] = mapped_column(Float)
    program: Mapped[Program] = relationship(back_populates="authorizations")

    def is_live(self, now: datetime | None = None) -> bool:
        now = now or _now()
        return self.revoked_at is None and self.expires_at > now


# --------------------------------------------------------------------------- scans/DAG
class Scan(PKMixin, TenantMixin, Base):
    __tablename__ = "scans"
    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False
    )
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("authorizations.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"), default=ScanStatus.PENDING, nullable=False
    )
    aggressiveness: Mapped[Aggressiveness] = mapped_column(
        pg_enum(Aggressiveness, "aggressiveness"), default=Aggressiveness.SAFE, nullable=False
    )
    scan_mode: Mapped[str] = mapped_column(String(16), default="connect")  # connect|syn
    config: Mapped[dict] = mapped_column(JSONB, default=dict)  # per-stage toggles
    scope_snapshot_hash: Mapped[str | None] = mapped_column(String(64))  # frozen at start
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stages: Mapped[list[ScanStage]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanStage(PKMixin, TenantMixin, Base):
    __tablename__ = "scan_stages"
    __table_args__ = (UniqueConstraint("scan_id", "name", name="uq_stage_scan_name"),)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "subdomains"
    status: Mapped[StageStatus] = mapped_column(
        pg_enum(StageStatus, "stage_status"), default=StageStatus.BLOCKED, nullable=False
    )
    total: Mapped[int] = mapped_column(Integer, default=0)
    done: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    scan: Mapped[Scan] = relationship(back_populates="stages")


# --------------------------------------------------------------------------- results
class Subdomain(PKMixin, TenantMixin, Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("scan_id", "hostname", name="uq_subdomain_scan_host"),)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(400), nullable=False)
    source: Mapped[str | None] = mapped_column(String(80))  # subfinder/brute/…
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class DNSRecord(PKMixin, TenantMixin, Base):
    __tablename__ = "dns_records"
    __table_args__ = (
        UniqueConstraint("scan_id", "hostname", "record_type", "value", name="uq_dns"),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(400), nullable=False)
    record_type: Mapped[str] = mapped_column(String(16), nullable=False)  # A/AAAA/CNAME/…
    value: Mapped[str] = mapped_column(String(400), nullable=False)


class Service(PKMixin, TenantMixin, Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("scan_id", "ip", "port", "protocol", name="uq_service"),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(400))
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp", nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(120))
    product: Mapped[str | None] = mapped_column(String(200))
    version: Mapped[str | None] = mapped_column(String(120))


class TLSInfo(PKMixin, TenantMixin, Base):
    __tablename__ = "tls_info"
    __table_args__ = (UniqueConstraint("scan_id", "hostname", "port", name="uq_tls"),)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(400), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=443, nullable=False)
    tls_version: Mapped[str | None] = mapped_column(String(32))
    cert_issuer: Mapped[str | None] = mapped_column(String(400))
    cert_subject: Mapped[str | None] = mapped_column(String(400))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    self_signed: Mapped[bool | None] = mapped_column(Boolean)
    expired: Mapped[bool | None] = mapped_column(Boolean)
    weak_protocol: Mapped[bool | None] = mapped_column(Boolean)


class HTTPEndpoint(PKMixin, TenantMixin, Base):
    __tablename__ = "http_endpoints"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_endpoint_scan_url"),)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(500))
    content_length: Mapped[int | None] = mapped_column(BigInteger)
    waf_vendor: Mapped[str | None] = mapped_column(String(120))
    cdn: Mapped[str | None] = mapped_column(String(120))
    screenshot_path: Mapped[str | None] = mapped_column(Text)


class Technology(PKMixin, TenantMixin, Base):
    __tablename__ = "technologies"
    __table_args__ = (
        UniqueConstraint("scan_id", "url", "name", "version", name="uq_tech"),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    layer: Mapped[str | None] = mapped_column(String(20))  # frontend/backend/server/cms
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str | None] = mapped_column(String(80))
    cpe: Mapped[str | None] = mapped_column(String(300))


class Parameter(PKMixin, TenantMixin, Base):
    __tablename__ = "parameters"
    __table_args__ = (
        UniqueConstraint("scan_id", "url", "name", "method", name="uq_param"),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    param_in: Mapped[str | None] = mapped_column(String(20))  # query/body/header/path
    reflected: Mapped[bool | None] = mapped_column(Boolean)


class Secret(PKMixin, TenantMixin, Base):
    """Never stores plaintext by default: mask + sha256 + detector + location.

    Optional full value goes in ciphertext (envelope-encrypted), off by default.
    """

    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("scan_id", "sha256", "location", name="uq_secret"),)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    detector: Mapped[str] = mapped_column(String(120), nullable=False)
    redacted_match: Mapped[str] = mapped_column(String(120), nullable=False)  # mask only
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    location: Mapped[str] = mapped_column(Text, nullable=False)  # url / file:line
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ciphertext: Mapped[bytes | None] = mapped_column()  # NULL unless full-retention opt-in


class CVE(PKMixin, Base):
    """Global CVE reference data (not tenant-scoped)."""

    __tablename__ = "cves"
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(120))
    severity: Mapped[Severity | None] = mapped_column(pg_enum(Severity, "cve_severity"))
    summary: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TechnologyCVE(PKMixin, TenantMixin, Base):
    __tablename__ = "technology_cves"
    __table_args__ = (UniqueConstraint("technology_id", "cve_id", name="uq_tech_cve"),)
    technology_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("technologies.id", ondelete="CASCADE"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String(32), ForeignKey("cves.cve_id"), nullable=False)
    match_source: Mapped[str | None] = mapped_column(String(60))  # cpe/version-range


class Finding(PKMixin, TenantMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "dedup_key", name="uq_finding_dedup"),
        # DB-level backstop for the honesty invariant: candidate-capped types can never
        # be stored as confirmed even if application code is bypassed.
        CheckConstraint(
            "NOT (confidence = 'confirmed' AND type IN "
            "('idor','broken_access_control','business_logic','injection_candidate',"
            "'sqli_candidate','xss_candidate','ssrf_candidate','open_redirect_candidate'))",
            name="ck_finding_candidate_cap",
        ),
        Index("ix_finding_scan_sev", "scan_id", "severity"),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "severity"), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(
        pg_enum(Confidence, "confidence"), nullable=False
    )
    status: Mapped[FindingStatus] = mapped_column(
        pg_enum(FindingStatus, "finding_status"), default=FindingStatus.NEW, nullable=False
    )
    cvss: Mapped[float | None] = mapped_column(Float)
    cve_id: Mapped[str | None] = mapped_column(String(32))
    cwe: Mapped[str | None] = mapped_column(String(20))
    target: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(200), nullable=False)  # stable across re-runs

    def __init__(self, **kw):
        # Application-level enforcement of the honesty invariant (paired with the DB
        # CheckConstraint). Refuses to construct a confirmed finding for a capped type.
        t = kw.get("type")
        c = kw.get("confidence")
        if t in CANDIDATE_CAPPED_TYPES and c == Confidence.CONFIRMED:
            raise ValueError(
                f"finding type {t!r} may never be 'confirmed' — hard-capped at 'candidate'"
            )
        if t not in CONFIRMABLE_TYPES and c == Confidence.CONFIRMED:
            raise ValueError(
                f"finding type {t!r} is not in CONFIRMABLE_TYPES; cannot be 'confirmed'"
            )
        super().__init__(**kw)


class ReportExport(PKMixin, TenantMixin, Base):
    __tablename__ = "report_exports"
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    fmt: Mapped[str] = mapped_column(String(10), nullable=False)  # html/pdf/json
    path: Mapped[str] = mapped_column(Text, nullable=False)


class AuditLog(PKMixin, TenantMixin, Base):
    """Append-only, hash-chained record — the legal trail for a run."""

    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("scan_id", "seq", name="uq_audit_seq"),
        Index("ix_audit_scan_seq", "scan_id", "seq"),
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)  # secrets already masked
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


# Tables that carry org_id and therefore get RLS policies applied in the migration.
TENANT_TABLES: tuple[str, ...] = (
    "memberships",
    "programs",
    "scope_rules",
    "authorizations",
    "scans",
    "scan_stages",
    "subdomains",
    "dns_records",
    "services",
    "tls_info",
    "http_endpoints",
    "technologies",
    "parameters",
    "secrets",
    "technology_cves",
    "findings",
    "report_exports",
    "audit_log",
)
