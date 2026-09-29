// Pure gating logic for the AuthorizationGate + scan wizard. No React here on purpose:
// the rule "Start is disabled until authorization is attested" is safety-critical, so it
// lives in a pure, unit-tested function that the UI merely reflects.

export const REQUIRED_PHRASE = "I AM AUTHORIZED";

export interface AttestationState {
  authorizedBy: string; // free text: who authorized (non-empty)
  programConfirmed: boolean; // program authorizes automated testing
  scopeConfirmed: boolean; // targets are within declared scope
  rulesConfirmed: boolean; // will honor rate limits / rules of engagement
  typedConfirmation: string; // must match REQUIRED_PHRASE (case-insensitive, trimmed)
}

export const emptyAttestation = (): AttestationState => ({
  authorizedBy: "",
  programConfirmed: false,
  scopeConfirmed: false,
  rulesConfirmed: false,
  typedConfirmation: "",
});

export function attestationComplete(s: AttestationState): boolean {
  return (
    s.authorizedBy.trim().length > 0 &&
    s.programConfirmed &&
    s.scopeConfirmed &&
    s.rulesConfirmed &&
    s.typedConfirmation.trim().toUpperCase() === REQUIRED_PHRASE
  );
}

// --- wizard step model ------------------------------------------------------
export type Aggressiveness = "safe" | "normal" | "aggressive";

export interface WizardState {
  domains: string[];
  scopeRules: { kind: string; action: "include" | "exclude"; value: string }[];
  aggressiveness: Aggressiveness;
  activeProbes: boolean;
  fuzzing: boolean;
  attestation: AttestationState;
  // What the selected program's authorization record permits:
  allowsActiveTesting: boolean;
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$/i;

export const isValidDomain = (d: string): boolean => DOMAIN_RE.test(d.trim());

export function domainsValid(domains: string[]): boolean {
  const cleaned = domains.map((d) => d.trim()).filter(Boolean);
  return cleaned.length > 0 && cleaned.every(isValidDomain);
}

export function scopeValid(rules: WizardState["scopeRules"]): boolean {
  return rules.some((r) => r.action === "include" && r.value.trim().length > 0);
}

// Sharp modules require the authorization record to permit active testing. This mirrors the
// backend gate; the UI must never let a user arm active/fuzzing without that permission.
export function aggressivenessValid(s: WizardState): boolean {
  const wantsSharp = s.activeProbes || s.fuzzing || s.aggressiveness === "aggressive";
  if (wantsSharp && !s.allowsActiveTesting) return false;
  return true;
}

export function stepValid(s: WizardState, step: number): boolean {
  switch (step) {
    case 0:
      return domainsValid(s.domains);
    case 1:
      return scopeValid(s.scopeRules);
    case 2:
      return aggressivenessValid(s);
    case 3:
      return attestationComplete(s.attestation);
    default:
      return false;
  }
}

export function canStart(s: WizardState): boolean {
  return [0, 1, 2, 3].every((step) => stepValid(s, step));
}
