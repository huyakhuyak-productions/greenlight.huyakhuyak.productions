import type { Finding, Rule } from '../types';

// Known-prefix credential patterns. Each is unique enough that a hit is
// near-certainly a real (or template-real) key — so severity = block.
//
// Source: Trufflehog, Gitleaks, GitHub's official secret-scanning docs.
const PATTERNS: ReadonlyArray<{
  ruleId: string;
  title: string;
  re: RegExp;
}> = [
  {
    ruleId: 'credentials.aws_access_key',
    title: 'AWS access key ID',
    // AKIA / ASIA / AGPA / AIDA / AROA / AIPA / ANPA / ANVA + 16+ alnum chars.
    // Greedy `{16,}` (instead of {16}\b) lets us still flag the key when it's
    // pasted with stray trailing alnum that would otherwise defeat the
    // word-boundary anchor. Real keys are 20 chars; >20 alnum is even more
    // suspicious, not less.
    re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16,}/,
  },
  {
    ruleId: 'credentials.github_token',
    // GitHub PAT prefixes: ghp (PAT), ghs (server-to-server), gho (oauth),
    // ghr (refresh), ghu (user-to-server), and the new fine-grained github_pat_.
    title: 'GitHub access token',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/,
  },
  {
    ruleId: 'credentials.slack_token',
    title: 'Slack token',
    // Legacy: xox[abposru]-...-..., new app-level: xapp-1-..., refresh-rotated: xoxe.xox?-...
    re: /\b(?:xox[abposru]-[A-Za-z0-9-]{10,}-[A-Za-z0-9-]{10,}|xapp-[0-9]+-[A-Za-z0-9-]{8,}|xoxe\.xox[abposru]-[A-Za-z0-9.-]{10,})/,
  },
  {
    ruleId: 'credentials.stripe_key',
    title: 'Stripe API key',
    // sk/pk/rk_(live|test)_…  + whsec_ webhook signing secrets.
    re: /\b(?:(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{32,})\b/,
  },
  {
    ruleId: 'credentials.google_api_key',
    title: 'Google API key',
    // Real Google API keys are 39 chars (AIza + 35). Greedy `{35,}` so stray
    // trailing alnum doesn't defeat the match — same reasoning as the AWS fix.
    re: /\bAIza[0-9A-Za-z_-]{35,}/,
  },
  {
    ruleId: 'credentials.private_key_block',
    title: 'PEM private key block',
    // PEM/PKCS armour for any private key variant: RSA, DSA, EC, OpenSSH, generic.
    re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----/,
  },
];

const REMEDIATION =
  'Treat this credential as compromised. Rotate it now, then commit the new value through your secrets manager rather than pasting it into a terminal.';

export const credentialsRule: Rule = {
  id: 'credentials',
  category: 'credentials',
  appliesTo: 'any',
  run(input) {
    const findings: Finding[] = [];

    for (const p of PATTERNS) {
      const m = input.match(p.re);
      if (!m || m.index == null) continue;
      findings.push({
        ruleId: p.ruleId,
        category: 'credentials',
        severity: 'block',
        title: p.title,
        message:
          'A pattern matching a real credential is present in this input. If you paste this anywhere — terminal, chat, ticket — that secret is now exposed.',
        evidence: m[0],
        span: [m.index, m.index + m[0].length],
        remediation: REMEDIATION,
      });
    }

    return findings;
  },
};
