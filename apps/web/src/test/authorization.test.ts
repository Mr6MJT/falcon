import { describe, expect, it } from "vitest";
import {
  type WizardState,
  attestationComplete,
  canStart,
  domainsValid,
  emptyAttestation,
  isValidDomain,
  REQUIRED_PHRASE,
  scopeValid,
  stepValid,
} from "@/lib/authorization";

const fullAttestation = () => ({
  authorizedBy: "Security Team",
  programConfirmed: true,
  scopeConfirmed: true,
  rulesConfirmed: true,
  typedConfirmation: REQUIRED_PHRASE,
});

describe("attestationComplete", () => {
  it("is false for an empty attestation", () => {
    expect(attestationComplete(emptyAttestation())).toBe(false);
  });

  it("requires every checkbox, a name, and the exact phrase", () => {
    const base = fullAttestation();
    expect(attestationComplete(base)).toBe(true);
    expect(attestationComplete({ ...base, authorizedBy: "  " })).toBe(false);
    expect(attestationComplete({ ...base, programConfirmed: false })).toBe(false);
    expect(attestationComplete({ ...base, scopeConfirmed: false })).toBe(false);
    expect(attestationComplete({ ...base, rulesConfirmed: false })).toBe(false);
    expect(attestationComplete({ ...base, typedConfirmation: "i am authorised" })).toBe(false);
  });

  it("accepts the phrase case-insensitively and trimmed", () => {
    expect(attestationComplete({ ...fullAttestation(), typedConfirmation: "  i am authorized " }))
      .toBe(true);
  });
});

describe("domain + scope validation", () => {
  it("validates domains", () => {
    expect(isValidDomain("example.com")).toBe(true);
    expect(isValidDomain("api.example.co.uk")).toBe(true);
    expect(isValidDomain("not a domain")).toBe(false);
    expect(isValidDomain("localhost")).toBe(false);
    expect(domainsValid([])).toBe(false);
    expect(domainsValid(["example.com", "bad domain"])).toBe(false);
    expect(domainsValid(["example.com"])).toBe(true);
  });

  it("requires at least one include rule for scope", () => {
    expect(scopeValid([])).toBe(false);
    expect(scopeValid([{ kind: "domain", action: "exclude", value: "x.com" }])).toBe(false);
    expect(scopeValid([{ kind: "domain", action: "include", value: "x.com" }])).toBe(true);
  });
});

describe("wizard gating — Start disabled until authorized", () => {
  const ready = (): WizardState => ({
    domains: ["example.com"],
    scopeRules: [{ kind: "wildcard", action: "include", value: "*.example.com" }],
    aggressiveness: "safe",
    activeProbes: false,
    fuzzing: false,
    attestation: fullAttestation(),
    allowsActiveTesting: false,
  });

  it("canStart is true only when all steps are valid", () => {
    expect(canStart(ready())).toBe(true);
  });

  it("canStart is false until the attestation is complete", () => {
    const s = ready();
    s.attestation = emptyAttestation();
    expect(canStart(s)).toBe(false);
    expect(stepValid(s, 3)).toBe(false);
  });

  it("blocks sharp modules unless the authz record permits active testing", () => {
    const s = ready();
    s.activeProbes = true;
    expect(stepValid(s, 2)).toBe(false); // not permitted -> invalid
    s.allowsActiveTesting = true;
    expect(stepValid(s, 2)).toBe(true);
  });

  it("blocks fuzzing and aggressive mode without permission too", () => {
    const s = ready();
    s.fuzzing = true;
    expect(canStart(s)).toBe(false);
    s.fuzzing = false;
    s.aggressiveness = "aggressive";
    expect(canStart(s)).toBe(false);
    s.allowsActiveTesting = true;
    expect(canStart(s)).toBe(true);
  });
});
