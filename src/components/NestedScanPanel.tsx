import { useState } from 'react';
import type { DownstreamScan } from '../lib/downstream';
import { hostOf } from '../lib/url';
import { FindingCard } from './FindingCard';

interface NestedScanPanelProps {
  url: string;
  downstream: DownstreamScan;
  onManualPaste?: (url: string, body: string) => void;
}

export function NestedScanPanel({ url, downstream, onManualPaste }: NestedScanPanelProps) {
  if (downstream.status === 'loading') {
    return <LoadingState url={url} />;
  }
  if (downstream.status === 'error') {
    return <ErrorState url={url} downstream={downstream} onManualPaste={onManualPaste} />;
  }
  return <SuccessState url={url} downstream={downstream} />;
}

function LoadingState({ url }: { url: string }) {
  const host = hostOf(url)?.host ?? url;
  return (
    <div
      data-finding-nested
      role="status"
      aria-live="polite"
      className="mt-3 pt-3 border-t font-mono text-[11px] uppercase tracking-[0.28em]"
      style={{
        borderColor: 'color-mix(in srgb, var(--flood-fg) 18%, transparent)',
        color: 'var(--flood-meta)',
      }}
    >
      <span className="inline-block w-2 h-2 mr-2 align-middle animate-pulse" style={{ backgroundColor: 'var(--flood-fg)' }} />
      fetching {host}…
    </div>
  );
}

function SuccessState({ url, downstream }: { url: string; downstream: DownstreamScan }) {
  const host = hostOf(url)?.host ?? url;
  const verdict = downstream.verdict;
  const body = downstream.fetchedBody ?? '';
  return (
    <div
      data-finding-nested
      aria-live="polite"
      className="mt-3 pt-3 border-t"
      style={{ borderColor: 'color-mix(in srgb, var(--flood-fg) 18%, transparent)' }}
    >
      <div
        className="font-mono text-[10px] uppercase tracking-[0.32em] mb-3"
        style={{ color: 'var(--flood-meta)' }}
      >
        <span aria-hidden="true">↳ </span>scanned {host} · {formatBodySize(body.length)}
      </div>

      {verdict && verdict.findings.length > 0 ? (
        <div className="space-y-3">
          {verdict.findings.map((f, i) => (
            <FindingCard
              key={`nested::${f.ruleId}::${f.span?.[0] ?? ''}::${f.span?.[1] ?? ''}::${i}`}
              finding={f}
            />
          ))}
        </div>
      ) : (
        <p
          className="font-mono text-[12px] leading-relaxed"
          style={{ color: 'var(--flood-fg)' }}
        >
          The script body reads as benign — but the engine only catches known patterns. Verify the host is who you think it is before you run it.
        </p>
      )}

      <details className="mt-3">
        <summary
          className="font-mono text-[10px] uppercase tracking-[0.28em] cursor-pointer select-none"
          style={{ color: 'var(--flood-meta)' }}
        >
          show fetched script ({body.split('\n').length} lines)
        </summary>
        <pre
          className="font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all px-3 py-2 mt-2 max-h-[420px] overflow-auto"
          style={{
            backgroundColor: 'color-mix(in srgb, var(--flood-fg) 10%, transparent)',
            color: 'var(--flood-fg)',
          }}
        >
          {body}
        </pre>
      </details>
    </div>
  );
}

function ErrorState({
  url,
  downstream,
  onManualPaste,
}: {
  url: string;
  downstream: DownstreamScan;
  onManualPaste?: (url: string, body: string) => void;
}) {
  const host = hostOf(url)?.host ?? url;
  const showManualPaste =
    downstream.errorKind === 'cors' ||
    downstream.errorKind === 'network' ||
    downstream.errorKind === 'http';

  return (
    <div
      data-finding-nested
      aria-live="polite"
      className="mt-3 pt-3 border-t"
      style={{ borderColor: 'color-mix(in srgb, var(--flood-fg) 18%, transparent)' }}
    >
      <div
        className="font-mono text-[10px] uppercase tracking-[0.32em] mb-2"
        style={{ color: 'var(--flood-meta)' }}
      >
        <span aria-hidden="true">↳ </span>couldn't fetch {host}
      </div>
      <p
        className="font-mono text-[12px] leading-relaxed"
        style={{ color: 'var(--flood-fg)' }}
      >
        {downstream.errorReason}
      </p>

      {showManualPaste && onManualPaste !== undefined && (
        <ManualPasteAffordance url={url} onSubmit={(body) => onManualPaste(url, body)} />
      )}
    </div>
  );
}

function ManualPasteAffordance({
  url,
  onSubmit,
}: {
  url: string;
  onSubmit: (body: string) => void;
}) {
  const [body, setBody] = useState('');
  const handle = () => {
    if (body.trim().length === 0) return;
    onSubmit(body);
  };
  const inputId = `manual-paste-${hashUrl(url)}`;
  return (
    <div className="mt-3">
      <label
        htmlFor={inputId}
        className="font-mono text-[10px] uppercase tracking-[0.32em] block mb-2"
        style={{ color: 'var(--flood-meta)' }}
      >
        paste the script body here
      </label>
      <textarea
        id={inputId}
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="off"
        value={body}
        onChange={(e) => setBody(e.target.value)}
        placeholder={`# run \`curl -fsSL ${url}\` in your terminal, then paste the output here`}
        className="block w-full min-h-[120px] p-3 font-mono text-[11px] leading-relaxed border placeholder:opacity-40"
        style={{
          color: 'var(--flood-fg)',
          backgroundColor: 'color-mix(in srgb, var(--flood-fg) 6%, transparent)',
          borderColor: 'color-mix(in srgb, var(--flood-fg) 25%, transparent)',
        }}
      />
      <button
        type="button"
        onClick={handle}
        disabled={body.trim().length === 0}
        className="mt-2 font-mono text-[10px] uppercase tracking-[0.32em] px-3 py-2 border disabled:opacity-40 disabled:cursor-not-allowed"
        style={{
          color: 'var(--flood-fg)',
          borderColor: 'color-mix(in srgb, var(--flood-fg) 60%, transparent)',
        }}
      >
        scan pasted body<span aria-hidden="true"> →</span>
      </button>
    </div>
  );
}

function formatBodySize(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)} kB`;
  return `${n} chars`;
}

function hashUrl(url: string): string {
  let h = 0;
  for (let i = 0; i < url.length; i++) h = ((h << 5) - h + url.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}
