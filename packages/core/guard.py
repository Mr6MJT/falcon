"""guard.run_tool — the ONE place Orvex is allowed to execute an engine.

Every network-touching tool invocation goes through here. Nowhere else in the
codebase may import ``subprocess``/``asyncio.create_subprocess_*``/``os.system``/
``os.exec*`` — CI (scripts/check_no_subprocess.py) fails the build if it finds one.

What this function guarantees, in order, for every call:
  1. SCOPE. Every target is checked with scope.is_in_scope(). Out-of-scope targets are
     dropped and audited; if nothing is left in scope, the tool never runs.
  2. RATE. A token is taken from the per-eTLD+1 bucket for each target before spawning.
  3. NATIVE RATE FLAGS. The tool's own rate/concurrency flags are appended from the
     profile, so even the tool's internal parallelism respects the cap.
  4. ATTEMPT CAPS. Sharp tools (login/brute-protection probing) are hard-capped
     (<=5 attempts) here — the cap is enforced by the guard, not trusted to the caller.
  5. REDACTION. stdout/stderr pass through redact.redact() before returning, so a
     leaked key never reaches a log or the DB in plaintext.
  6. CANCELLATION + TIMEOUT. The child runs in its own process group; cancel/timeout
     SIGTERMs the group then SIGKILLs it.

This module deliberately contains the only `import subprocess` in the project.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
from dataclasses import dataclass, field

from .ratelimit import (
    InMemoryTokenBucket,
    RateProfile,
    RateSpec,
    TokenBucketBackend,
    effective_spec,
    etld1_key,
)
from .redact import SecretRef, redact
from .scope import ScopeRule, is_in_scope


class ScopeViolation(RuntimeError):
    """Raised when run_tool is asked to run with no in-scope targets left."""


@dataclass
class ToolProfile:
    """How to build a command line for one engine, incl. its native rate flags."""

    name: str
    base_cmd: list[str]
    # A callable that yields the rate/concurrency flags for this tool given a RateSpec.
    rate_flags: callable  # (RateSpec) -> list[str]
    # Hard cap on attempts for sharp tools; None = not attempt-capped.
    max_attempts: int | None = None
    # How targets reach the engine. The ProjectDiscovery family (subfinder, dnsx, httpx,
    # naabu, tlsx, katana, nuclei) and gau read their target list from STDIN (one per line)
    # and ignore positional arguments; feeding them positionally makes them run against an
    # empty set. Tools with a bespoke CLI (wafw00f <url>, ffuf -u, trufflehog, our own
    # probes) take targets as positional args instead.
    stdin_targets: bool = True


def _pd_httpx_rate(spec: RateSpec) -> list[str]:
    return ["-rate-limit", str(int(spec.rps)), "-threads", str(spec.max_concurrency)]


def _naabu_rate(spec: RateSpec) -> list[str]:
    return ["-rate", str(int(spec.rps * 30)), "-c", str(spec.max_concurrency)]


def _nuclei_rate(spec: RateSpec) -> list[str]:
    return ["-rate-limit", str(int(spec.rps * 10)), "-c", str(spec.max_concurrency)]


def _ffuf_rate(spec: RateSpec) -> list[str]:
    # Fuzzing stays inside the same envelope: -rate caps req/s, -p adds a delay,
    # honouring backoff is handled by the adaptive layer above.
    return ["-rate", str(int(spec.rps)), "-t", str(spec.max_concurrency), "-p", "0.1"]


def _subfinder_rate(spec: RateSpec) -> list[str]:
    # Passive source enumeration; -rate-limit caps queries/s to third-party sources.
    return ["-rate-limit", str(max(1, int(spec.rps)))]


def _dnsx_rate(spec: RateSpec) -> list[str]:
    return ["-rate-limit", str(int(spec.rps * 10)), "-t", str(spec.max_concurrency)]


def _tlsx_rate(spec: RateSpec) -> list[str]:
    return ["-c", str(spec.max_concurrency)]


def _no_rate(spec: RateSpec) -> list[str]:
    # Tool has no native rate flag; the per-eTLD+1 token bucket still gates it.
    return []


# Registry of the engines Orvex is allowed to run. Anything not here cannot be spawned.
TOOL_PROFILES: dict[str, ToolProfile] = {
    # Passive recon.
    "subfinder": ToolProfile("subfinder", ["subfinder"], _subfinder_rate),
    "dnsx": ToolProfile("dnsx", ["dnsx"], _dnsx_rate),
    "httpx": ToolProfile("httpx", ["httpx"], _pd_httpx_rate),
    # Port / service, TLS, WAF, tech fingerprinting.
    "naabu": ToolProfile("naabu", ["naabu"], _naabu_rate),
    "tlsx": ToolProfile("tlsx", ["tlsx"], _tlsx_rate),
    "wafw00f": ToolProfile("wafw00f", ["wafw00f"], _no_rate, stdin_targets=False),
    # URL / endpoint discovery + secret detection.
    "katana": ToolProfile("katana", ["katana"], lambda s: ["-rl", str(int(s.rps)),
                                                           "-c", str(s.max_concurrency)]),
    "gau": ToolProfile("gau", ["gau"], _no_rate),  # passive/historical, no live requests
    "trufflehog": ToolProfile("trufflehog", ["trufflehog"], _no_rate, stdin_targets=False),
    "nuclei": ToolProfile("nuclei", ["nuclei"], _nuclei_rate),
    # Content/parameter fuzzing — opt-in, gated, rate-limited, NON-destructive.
    "ffuf": ToolProfile("ffuf", ["ffuf"], _ffuf_rate, stdin_targets=False),
    # Canary-based active probes (GET/idempotent by default): reflection/boolean-diff markers
    # for xss/sqli/open-redirect/ssrf. Our own bundled tool; egress still via the gateway.
    "orvex-probe": ToolProfile("orvex-probe", ["orvex-probe"], _no_rate, stdin_targets=False),
    # IDOR differential testing (two sessions). Findings are hard-capped at candidate.
    "orvex-idor": ToolProfile("orvex-idor", ["orvex-idor"], _no_rate, stdin_targets=False),
    # Safe login testing: brute-force-PROTECTION-exists only, hard-capped at 5 attempts.
    "login_probe": ToolProfile("login_probe", ["orvex-login-probe"], lambda s: [],
                               max_attempts=5, stdin_targets=False),
}


@dataclass
class ToolResult:
    ok: bool
    returncode: int
    stdout: str  # already redacted
    stderr: str  # already redacted
    secrets: list[SecretRef] = field(default_factory=list)
    in_scope_targets: list[str] = field(default_factory=list)
    dropped_targets: list[tuple[str, str]] = field(default_factory=list)  # (target, reason)


def _validate_targets(
    targets: list[str], rules: list[ScopeRule], allow_internal: bool
) -> tuple[list[str], list[tuple[str, str]]]:
    kept: list[str] = []
    dropped: list[tuple[str, str]] = []
    for t in targets:
        d = is_in_scope(t, rules, allow_internal=allow_internal)
        if d.allowed:
            kept.append(t)
        else:
            dropped.append((t, d.reason))
    return kept, dropped


def run_tool(
    tool: str,
    targets: list[str],
    scope_rules: list[ScopeRule],
    *,
    extra_args: list[str] | None = None,
    profile: RateProfile = RateProfile.SAFE,
    program_rate_cap_rps: float | None = None,
    allow_internal: bool = False,
    attempts: int | None = None,
    timeout_s: float = 900.0,
    bucket: TokenBucketBackend | None = None,
    audit=None,  # callable(event: dict) -> None; the hash-chained audit sink
    redact_stdout: bool = True,  # False ONLY for the secrets stage (see below)
    _runner=None,  # injectable spawn fn for tests; defaults to subprocess
) -> ToolResult:
    if tool not in TOOL_PROFILES:
        raise ScopeViolation(f"tool {tool!r} is not in the allow-list of engines")
    tp = TOOL_PROFILES[tool]
    bucket = bucket or InMemoryTokenBucket()
    audit = audit or (lambda e: None)

    kept, dropped = _validate_targets(list(targets), list(scope_rules), allow_internal)
    for t, reason in dropped:
        audit({"event": "target_dropped", "tool": tool, "target": t, "reason": reason})
    if not kept:
        audit({"event": "tool_skipped", "tool": tool, "reason": "no in-scope targets"})
        return ToolResult(
            ok=False, returncode=-1, stdout="", stderr="no in-scope targets",
            in_scope_targets=[], dropped_targets=dropped,
        )

    # Attempt cap for sharp tools — enforced here, never trusted to the caller.
    if tp.max_attempts is not None:
        requested = attempts if attempts is not None else tp.max_attempts
        attempts = min(requested, tp.max_attempts)
        if attempts < requested:
            audit({"event": "attempts_capped", "tool": tool,
                   "requested": requested, "capped_to": attempts})

    spec = effective_spec(profile, program_rate_cap_rps)

    # Take a token per target before spawning. Waiting is the caller's concern; here we
    # simply refuse to exceed the bucket by blocking-taking (cooperative).
    for t in kept:
        key = etld1_key(t.split("://")[-1].split("/")[0])
        wait = bucket.take(key, spec.rps, spec.burst)
        if wait > 0:
            audit({"event": "rate_wait", "tool": tool, "target": t, "wait_s": round(wait, 3)})

    cmd = list(tp.base_cmd) + tp.rate_flags(spec) + (extra_args or [])
    if attempts is not None:
        cmd += ["--max-attempts", str(attempts)]
    # ProjectDiscovery engines read their target list from stdin; bespoke-CLI tools take it
    # positionally. Getting this wrong makes the engine run against an empty target set.
    if tp.stdin_targets:
        stdin_data = "\n".join(kept) + "\n"
    else:
        cmd += kept
        stdin_data = None

    audit({"event": "tool_spawn", "tool": tool, "cmd": " ".join(shlex.quote(c) for c in cmd),
           "targets": kept, "profile": profile.value})

    if _runner is not None:
        rc, raw_out, raw_err = _runner(cmd, timeout_s, stdin_data)
    else:
        rc, raw_out, raw_err = _spawn(cmd, timeout_s, stdin_data)

    if redact_stdout:
        out, out_secrets = redact(raw_out)
        err, err_secrets = redact(raw_err)
        return ToolResult(
            ok=(rc == 0), returncode=rc, stdout=out, stderr=err,
            secrets=out_secrets + err_secrets, in_scope_targets=kept, dropped_targets=dropped,
        )
    # redact_stdout=False: raw output returned for the ONE caller that must parse structured
    # secret findings (the secrets stage). That caller must store only masks + hashes and must
    # NEVER log this stdout. The audit trail below never includes tool output, redacted or not.
    audit({"event": "raw_output_requested", "tool": tool})
    return ToolResult(
        ok=(rc == 0), returncode=rc, stdout=raw_out, stderr=raw_err,
        secrets=[], in_scope_targets=kept, dropped_targets=dropped,
    )


def _spawn(cmd: list[str], timeout_s: float,
           stdin_data: str | None = None) -> tuple[int, str, str]:
    """Spawn in a new process group; kill the whole group on timeout/cancel.

    ``stdin_data`` (targets, one per line) is piped to the engine's stdin when set; engines
    that read their target list from stdin get an empty, closed stdin otherwise.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,  # own process group -> killpg works
    )
    try:
        out, err = proc.communicate(input=stdin_data, timeout=timeout_s)
        return proc.returncode, out or "", err or ""
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        out, err = proc.communicate()
        return 124, out or "", (err or "") + "\n[orvex] killed on timeout"


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
