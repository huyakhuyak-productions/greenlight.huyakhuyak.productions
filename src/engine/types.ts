export type Severity = 'allow' | 'warn' | 'block';

export type Kind = 'command' | 'url' | 'config';

export type Category =
  | 'pipe-to-shell'
  | 'homograph'
  | 'base64-exec'
  | 'terminal-injection'
  | 'insecure-transport'
  | 'exfiltration'
  | 'credentials'
  | 'command-safety'
  | 'steganography'
  | 'config-injection'
  | 'ecosystem'
  | 'environment'
  | 'code-scan'
  | 'post-compromise'
  | 'path-analysis';

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Exclude<Severity, 'allow'>;
  title: string;
  message: string;
  evidence?: string;
  span?: [number, number];
  remediation?: string;
}

export interface Verdict {
  severity: Severity;
  findings: Finding[];
  kind: Kind;
}

export type RuleFn = (input: string, kind: Kind) => Finding[];

export interface Rule {
  id: string;
  category: Category;
  appliesTo: ReadonlyArray<Kind> | 'any';
  run: RuleFn;
}

const SEVERITY_RANK: Record<Severity, number> = { allow: 0, warn: 1, block: 2 };

export function maxSeverity(severities: Iterable<Severity>): Severity {
  let max: Severity = 'allow';
  for (const s of severities) {
    if (SEVERITY_RANK[s] > SEVERITY_RANK[max]) max = s;
  }
  return max;
}
