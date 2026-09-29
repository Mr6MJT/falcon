"""Findings engine: classification honesty (pure) + stage population/dedup/CVE catalog."""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.findings import classify_nuclei, finding_from_nuclei
from packages.core.guard import ToolResult
from packages.core.models import (
    CVE,
    Authorization,
    AuthorizationType,
    Confidence,
    Finding,
    HTTPEndpoint,
    Organization,
    Program,
    Scan,
    Severity,
)
from packages.core.scope import RuleAction, RuleKind, ScopeRule
from packages.core.stages import StageContext, run_findings

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)

# nuclei-style results.
NUCLEI_OUT = "\n".join([
    # matcher-based exposure -> confirmed
    '{"template-id":"git-config","info":{"name":"Git Config Exposure","severity":"medium",'
    '"tags":["exposure","config"]},"matched-at":"https://www.example.com/.git/config",'
    '"request":"GET /.git/config","response":"[core]"}',
    # CVE template -> candidate, with cve-id + cvss
    '{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical",'
    '"tags":["cve"],"classification":{"cve-id":["CVE-2021-1234"],"cvss-score":9.8,'
    '"cwe-id":["CWE-78"]}},"matched-at":"https://api.example.com/"}',
    # tls issue -> confirmed
    '{"template-id":"tls-version","info":{"name":"TLS 1.0","severity":"low","tags":["ssl","tls"]},'
    '"matched-at":"https://www.example.com"}',
])


def _runner(out=NUCLEI_OUT):
    def run(tool, targets, **kw):
        return ToolResult(ok=True, returncode=0, stdout=out if tool == "nuclei" else "",
                          stderr="", in_scope_targets=list(targets))
    return run


# --- pure classification ----------------------------------------------------
def test_cve_templates_are_candidate():
    ftype, conf = classify_nuclei(
        {"classification": {"cve-id": ["CVE-2020-1"]}}, ["cve"])
    assert ftype == "cve" and conf == Confidence.CANDIDATE


def test_matcher_based_are_confirmed():
    assert classify_nuclei({}, ["exposure"]) == ("exposure", Confidence.CONFIRMED)
    assert classify_nuclei({}, ["ssl"]) == ("tls_issue", Confidence.CONFIRMED)
    assert classify_nuclei({}, ["misconfig"]) == ("misconfiguration", Confidence.CONFIRMED)


def test_unknown_is_candidate():
    _, conf = classify_nuclei({}, ["something-new"])
    assert conf == Confidence.CANDIDATE


def test_finding_from_nuclei_maps_cve_and_cvss():
    obj = {
        "template-id": "CVE-2021-1234",
        "info": {"name": "X", "severity": "critical",
                 "tags": ["cve"], "classification": {"cve-id": ["CVE-2021-1234"],
                                                      "cvss-score": 9.8}},
        "matched-at": "https://api.example.com/",
    }
    row = finding_from_nuclei(obj)
    assert row["type"] == "cve" and row["confidence"] == Confidence.CANDIDATE
    assert row["cve_id"] == "CVE-2021-1234" and row["cvss"] == 9.8


# --- honesty invariant: the model refuses to construct a confirmed capped finding ----
def test_model_rejects_confirmed_idor():
    with pytest.raises(ValueError):
        Finding(type="idor", title="x", severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED, dedup_key="k")


# --- stage against the DB ---------------------------------------------------
@pytest.fixture
def session():
    eng = create_engine(OWNER_URL, future=True)
    try:
        with eng.connect() as c:
            c.execute(select(1))
    except OperationalError:
        pytest.skip("Postgres not reachable")
    s = sessionmaker(bind=eng, future=True)()
    s.begin()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def scan(session):
    org = Organization(name="t", slug=f"t-{uuid.uuid4().hex[:8]}")
    session.add(org)
    session.flush()
    prog = Program(org_id=org.id, name="p", slug=f"p-{uuid.uuid4().hex[:8]}")
    session.add(prog)
    session.flush()
    authz = Authorization(org_id=org.id, program_id=prog.id, authorized_by="me",
                          authorization_type=AuthorizationType.BUG_BOUNTY,
                          expires_at=datetime.now(UTC) + timedelta(days=30))
    session.add(authz)
    session.flush()
    sc = Scan(org_id=org.id, program_id=prog.id, authorization_id=authz.id, config={})
    session.add(sc)
    session.flush()
    session.add(HTTPEndpoint(org_id=org.id, scan_id=sc.id,
                             url="https://www.example.com", status_code=200))
    session.flush()
    return sc


def _ctx(session, scan):
    rules = [ScopeRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com")]
    return StageContext(session=session, scan=scan, scope_rules=rules,
                        roots=["example.com"], run=_runner())


def test_findings_typed_deduped_with_cve_and_cvss(session, scan):
    run_findings(_ctx(session, scan))
    rows = session.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    by_type = {r.type: r for r in rows}
    assert by_type["exposure"].confidence == Confidence.CONFIRMED
    assert by_type["cve"].confidence == Confidence.CANDIDATE
    assert by_type["cve"].cve_id == "CVE-2021-1234" and by_type["cve"].cvss == 9.8
    assert by_type["tls_issue"].confidence == Confidence.CONFIRMED
    # CVE catalog populated
    cve = session.execute(select(CVE).where(CVE.cve_id == "CVE-2021-1234")).scalar_one()
    assert cve.cvss_score == 9.8


def test_findings_rerun_no_duplicates(session, scan):
    run_findings(_ctx(session, scan))
    n1 = session.execute(
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)
    ).scalar()
    run_findings(_ctx(session, scan))
    n2 = session.execute(
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)
    ).scalar()
    assert n1 == n2 == 3


def test_db_blocks_confirmed_capped_finding(session, scan):
    # Raw insert bypassing the model must still be refused by the CheckConstraint.
    with pytest.raises(IntegrityError):
        session.execute(text(
            "INSERT INTO findings (id, org_id, scan_id, type, title, severity, confidence, "
            "status, evidence, dedup_key, created_at, updated_at) VALUES "
            "(gen_random_uuid(), :o, :s, 'idor', 'x', 'high', 'confirmed', 'new', '{}', 'k', "
            "now(), now())"
        ), {"o": scan.org_id, "s": scan.id})
    session.rollback()
    session.begin()
