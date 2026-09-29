"""Guard tests: scope drop, attempt caps, redaction — all enforced before/around spawn."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.guard import ScopeViolation, run_tool
from packages.core.ratelimit import RateProfile
from packages.core.scope import RuleAction, RuleKind, ScopeRule


def _scope():
    return [ScopeRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.lab.local")]


def _fake_runner(recorded, stdin_seen=None):
    def runner(cmd, timeout_s, stdin_data=None):
        recorded.append(cmd)
        if stdin_seen is not None:
            stdin_seen.append(stdin_data)
        # Pretend the tool printed a live-looking AWS key; guard must redact it.
        return 0, "found AKIAIOSFODNN7EXAMPLE in config", ""
    return runner


def test_out_of_scope_target_is_dropped_and_tool_not_run():
    recorded = []
    res = run_tool(
        "httpx",
        ["evil.attacker.net"],
        _scope(),
        _runner=_fake_runner(recorded),
    )
    assert res.ok is False
    assert recorded == []  # never spawned
    assert res.dropped_targets and "attacker.net" in res.dropped_targets[0][0]


def test_in_scope_target_runs_and_output_is_redacted():
    recorded = []
    res = run_tool(
        "httpx",
        ["api.lab.local", "evil.attacker.net"],
        _scope(),
        _runner=_fake_runner(recorded),
    )
    assert res.ok is True
    assert res.in_scope_targets == ["api.lab.local"]
    assert len(res.dropped_targets) == 1
    # Redaction: raw key must NOT appear; a masked ref must be recorded.
    assert "AKIAIOSFODNN7EXAMPLE" not in res.stdout
    assert "[REDACTED:aws_access_key_id" in res.stdout
    assert any(s.detector == "aws_access_key_id" for s in res.secrets)


def test_login_probe_attempts_hard_capped_at_five():
    recorded = []
    res = run_tool(
        "login_probe",
        ["auth.lab.local"],
        _scope(),
        attempts=100,  # caller asks for 100...
        _runner=_fake_runner(recorded),
    )
    assert res.ok is True
    # ...guard forces --max-attempts 5 onto the command line.
    assert "--max-attempts" in recorded[0]
    idx = recorded[0].index("--max-attempts")
    assert recorded[0][idx + 1] == "5"


def test_unknown_tool_refused():
    with pytest.raises(ScopeViolation):
        run_tool("rm-rf", ["api.lab.local"], _scope(), _runner=_fake_runner([]))


def test_safe_profile_appends_native_rate_flags():
    recorded = []
    run_tool("nuclei", ["api.lab.local"], _scope(),
             profile=RateProfile.SAFE, _runner=_fake_runner(recorded))
    assert "-rate-limit" in recorded[0]


def test_projectdiscovery_targets_go_to_stdin_not_argv():
    """PD engines read targets from stdin; they must NOT be appended as positional args."""
    recorded, stdin_seen = [], []
    run_tool("dnsx", ["a.lab.local", "b.lab.local"], _scope(),
             _runner=_fake_runner(recorded, stdin_seen))
    assert "a.lab.local" not in recorded[0]  # not on the command line
    assert stdin_seen[0] == "a.lab.local\nb.lab.local\n"  # piped via stdin


def test_bespoke_cli_targets_stay_positional():
    """wafw00f takes its URL positionally and gets no stdin payload."""
    recorded, stdin_seen = [], []
    run_tool("wafw00f", ["api.lab.local"], _scope(),
             _runner=_fake_runner(recorded, stdin_seen))
    assert recorded[0][-1] == "api.lab.local"  # positional
    assert stdin_seen[0] is None
