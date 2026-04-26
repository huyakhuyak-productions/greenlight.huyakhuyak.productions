import type { Finding, Kind, Rule, Verdict } from './types';
import { maxSeverity } from './types';

export function runRules(input: string, kind: Kind, rules: ReadonlyArray<Rule>): Verdict {
  const findings: Finding[] = [];

  for (const rule of rules) {
    if (rule.appliesTo !== 'any' && !rule.appliesTo.includes(kind)) continue;
    try {
      findings.push(...rule.run(input, kind));
    } catch {
      // A buggy rule must never take down the whole verdict — skip it silently.
      // Errors are surfaced via dev-tools console only, never to the user.
    }
  }

  const severity = findings.length === 0 ? 'allow' : maxSeverity(findings.map((f) => f.severity));
  return { severity, findings, kind };
}
