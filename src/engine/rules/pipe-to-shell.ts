import type { Finding, Rule } from '../types';

const FETCHER = '(?:curl|wget|fetch|http)';
const INTERPRETER =
  '(?:bash|sh|zsh|fish|ksh|dash|ash|python3?|ruby|perl|node|deno|bun|php|powershell|pwsh)';

const FETCHER_PIPE_TO_SHELL = new RegExp(
  `\\b${FETCHER}\\b[^\\n|]*(?:\\|\\s*[^|\\n]*?)*\\|\\s*${INTERPRETER}\\b`,
  'i',
);

const PROCESS_SUB = new RegExp(`\\b${INTERPRETER}\\b\\s*<\\(\\s*${FETCHER}\\b`, 'i');

const EVAL_SUBSTITUTION = new RegExp(
  `\\b(?:eval|source|\\.)\\b[^\\n]*\\$\\(\\s*${FETCHER}\\b`,
  'i',
);

const BACKTICK_FETCH = new RegExp(`\\b(?:eval|source)\\b[^\\n]*\`\\s*${FETCHER}\\b`, 'i');

function findMatch(
  input: string,
  re: RegExp,
): { evidence: string; span: [number, number] } | null {
  const m = input.match(re);
  if (!m || m.index == null) return null;
  return { evidence: m[0], span: [m.index, m.index + m[0].length] };
}

const REMEDIATION =
  'Download the script first, inspect it (`less ./install.sh`), then run it explicitly. Never trust a remote pipeline that runs unread code.';

export const pipeToShellRule: Rule = {
  id: 'pipe_to_shell.fetch_to_interpreter',
  category: 'pipe-to-shell',
  appliesTo: ['command'],
  run(input) {
    const findings: Finding[] = [];

    const direct = findMatch(input, FETCHER_PIPE_TO_SHELL);
    if (direct) {
      findings.push({
        ruleId: 'pipe_to_shell.fetch_to_interpreter',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Remote download piped to a shell',
        message:
          'A network fetch is being piped directly into a shell or interpreter. The script can change between when you read it and when you run it, and you cannot inspect it before execution.',
        evidence: direct.evidence,
        span: direct.span,
        remediation: REMEDIATION,
      });
    }

    const procsub = findMatch(input, PROCESS_SUB);
    if (procsub) {
      findings.push({
        ruleId: 'pipe_to_shell.process_substitution',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Process substitution executes a remote fetch',
        message:
          'Bash process substitution `<(curl ...)` runs the fetched output as if it were a local file. The remote contents are never persisted or inspected.',
        evidence: procsub.evidence,
        span: procsub.span,
        remediation: REMEDIATION,
      });
    }

    const ev = findMatch(input, EVAL_SUBSTITUTION) ?? findMatch(input, BACKTICK_FETCH);
    if (ev) {
      findings.push({
        ruleId: 'pipe_to_shell.eval_of_fetch',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Remote fetch evaluated as code',
        message:
          'A network fetch is being passed to `eval`, `source`, or backticks. The downloaded text is executed as shell code without inspection.',
        evidence: ev.evidence,
        span: ev.span,
        remediation: REMEDIATION,
      });
    }

    return findings;
  },
};
