import type { Finding } from '../engine';

const SEVERITY_LABEL: Record<Finding['severity'], string> = {
  warn: 'CAUTION',
  block: 'STOP',
};

const CATEGORY_LABEL: Record<Finding['category'], string> = {
  'pipe-to-shell': 'pipe → shell',
  homograph: 'homograph',
  'base64-exec': 'base64 → run',
  'terminal-injection': 'terminal injection',
  'insecure-transport': 'insecure transport',
  exfiltration: 'exfiltration',
  credentials: 'credentials',
  'command-safety': 'command safety',
  steganography: 'steganography',
  'config-injection': 'config injection',
  ecosystem: 'ecosystem',
  environment: 'environment',
  'code-scan': 'code scan',
  'post-compromise': 'post-compromise',
  'path-analysis': 'path analysis',
};

interface FindingCardProps {
  finding: Finding;
}

export function FindingCard({ finding }: FindingCardProps) {
  return (
    <article
      data-finding
      className="relative border-2 px-5 py-4"
      style={{
        borderColor: 'color-mix(in srgb, var(--flood-fg) 35%, transparent)',
        backgroundColor: 'color-mix(in srgb, var(--flood-fg) 4%, transparent)',
      }}
    >
      <header className="flex items-baseline justify-between gap-3 mb-2">
        <span
          className="font-mono text-[10px] uppercase tracking-[0.3em]"
          style={{ color: 'var(--flood-meta)' }}
        >
          {CATEGORY_LABEL[finding.category]}
        </span>
        <span
          className="font-mono text-[10px] uppercase tracking-[0.32em] px-2 py-[2px] border"
          style={{
            borderColor: 'color-mix(in srgb, var(--flood-fg) 60%, transparent)',
            color: 'var(--flood-fg)',
          }}
        >
          {SEVERITY_LABEL[finding.severity]}
        </span>
      </header>

      <h3
        className="font-display italic text-2xl leading-tight text-balance mb-2"
        style={{ color: 'var(--flood-fg)' }}
      >
        {finding.title}
      </h3>

      {finding.evidence !== undefined && finding.evidence.length > 0 && (
        <pre
          className="font-mono text-xs leading-relaxed whitespace-pre-wrap break-all px-3 py-2 mb-3"
          style={{
            backgroundColor: 'color-mix(in srgb, var(--flood-fg) 14%, transparent)',
            color: 'var(--flood-fg)',
          }}
        >
          {finding.evidence}
        </pre>
      )}

      <p
        className="font-mono text-[12px] leading-relaxed"
        style={{ color: 'var(--flood-fg)' }}
      >
        {finding.message}
      </p>

      {finding.remediation !== undefined && finding.remediation.length > 0 && (
        <p
          className="font-mono text-[11px] leading-relaxed mt-3 pt-3 border-t"
          style={{
            borderColor: 'color-mix(in srgb, var(--flood-fg) 18%, transparent)',
            color: 'var(--flood-meta)',
          }}
        >
          <span className="uppercase tracking-[0.28em] mr-2">do this →</span>
          <span className="normal-case">{finding.remediation}</span>
        </p>
      )}

      <footer
        className="font-mono text-[9px] uppercase tracking-[0.32em] mt-3 opacity-60"
        style={{ color: 'var(--flood-meta)' }}
      >
        rule::{finding.ruleId}
      </footer>
    </article>
  );
}
