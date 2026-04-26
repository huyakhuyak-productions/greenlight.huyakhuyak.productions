import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import gsap from 'gsap';
import { useValidator } from '../hooks/useValidator';
import { KindToggle } from './KindToggle';
import { VerdictWord } from './VerdictWord';
import { FindingCard } from './FindingCard';
import type { Severity } from '../engine';

const FLOOD: Record<Severity, { bg: string; fg: string; meta: string; rule: string }> = {
  allow: { bg: '#a6ff00', fg: '#0a0908', meta: '#0a0908', rule: '#0a0908' },
  warn: { bg: '#ffb800', fg: '#0a0908', meta: '#0a0908', rule: '#0a0908' },
  block: { bg: '#e63946', fg: '#f2ebe0', meta: '#f2ebe0', rule: '#f2ebe0' },
};

const NEUTRAL = { bg: '#0a0908', fg: '#f2ebe0', meta: '#d8d0c2', rule: '#2a2724' };

const VERDICT_LABEL: Record<Severity, string> = {
  allow: 'PROCEED',
  warn: 'PROCEED WITH CARE',
  block: 'DO NOT RUN',
};

function detailFor(severity: Severity, count: number, hasInput: boolean): string {
  if (!hasInput) return 'A static rules engine inspects your input locally. Nothing is sent anywhere.';
  if (severity === 'allow') {
    return 'No threats detected by any active rule. Verify the source independently before running.';
  }
  if (severity === 'warn') {
    return count === 1
      ? 'One item below deserves a second look before you paste this into a terminal.'
      : `${count} items below deserve a second look before you paste this into a terminal.`;
  }
  return count === 1
    ? 'This input matches a high-confidence attack pattern. Do not paste this into a terminal.'
    : `This input matches ${count} high-confidence attack patterns. Do not paste this into a terminal.`;
}

type CopyState = 'idle' | 'copied' | 'failed';

export function Validator() {
  const { input, setInput, kindOverride, setKindOverride, verdict, isPending } = useValidator();
  const rootRef = useRef<HTMLDivElement>(null);
  const scanRef = useRef<HTMLDivElement>(null);
  const [copyState, setCopyState] = useState<CopyState>('idle');

  const hasInput = input.trim().length > 0;
  const palette = useMemo(() => (hasInput ? FLOOD[verdict.severity] : NEUTRAL), [hasInput, verdict.severity]);

  // GSAP owns the four --flood-* CSS variables. We seed them once before paint
  // (so nothing flashes against an unset variable), then every later mutation
  // goes through the gsap.to tween below. The JSX inline style intentionally
  // does NOT include these variables — that would fight the tween on re-render.
  useLayoutEffect(() => {
    if (!rootRef.current) return;
    gsap.set(rootRef.current, {
      '--flood-bg': NEUTRAL.bg,
      '--flood-fg': NEUTRAL.fg,
      '--flood-meta': NEUTRAL.meta,
      '--flood-rule': NEUTRAL.rule,
    });
  }, []);

  // Initial reveal — staggered chrome on first mount. Uses fromTo with explicit
  // end-state + clearProps cleanup so React 19 StrictMode's mount→unmount→mount
  // cycle can never leave the elements stranded mid-animation.
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const reveals = root.querySelectorAll('[data-reveal]');
    if (reveals.length === 0) return;
    const tween = gsap.fromTo(
      reveals,
      { opacity: 0, y: 24 },
      {
        opacity: 1,
        y: 0,
        duration: 0.9,
        ease: 'expo.out',
        stagger: 0.06,
        overwrite: 'auto',
      },
    );
    return () => {
      tween.kill();
      gsap.set(reveals, { clearProps: 'opacity,transform' });
    };
  }, []);

  // Background color flood — animated as a CSS variable so the grain/scanline
  // overlays compose against it without re-painting children.
  useEffect(() => {
    if (!rootRef.current) return;
    const tween = gsap.to(rootRef.current, {
      '--flood-bg': palette.bg,
      '--flood-fg': palette.fg,
      '--flood-meta': palette.meta,
      '--flood-rule': palette.rule,
      duration: 0.45,
      ease: 'power2.inOut',
      overwrite: 'auto',
    });
    return () => {
      tween.kill();
    };
  }, [palette]);

  // Scan-line sweep — fires on each meaningful input change.
  useEffect(() => {
    if (!hasInput || !scanRef.current) return;
    const tween = gsap.fromTo(
      scanRef.current,
      { xPercent: -110, opacity: 0.6 },
      {
        xPercent: 110,
        opacity: 0,
        duration: 0.5,
        ease: 'power2.inOut',
        overwrite: 'auto',
      },
    );
    return () => {
      tween.kill();
    };
  }, [input, hasInput]);

  // Stagger the findings as ticker-tape cards.
  useEffect(() => {
    if (!rootRef.current) return;
    const cards = rootRef.current.querySelectorAll('[data-finding]');
    if (cards.length === 0) return;
    const tween = gsap.fromTo(
      cards,
      { y: 16, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.4, ease: 'expo.out', stagger: 0.04, overwrite: 'auto' },
    );
    return () => {
      tween.kill();
      gsap.set(cards, { clearProps: 'opacity,transform' });
    };
  }, [verdict.findings]);

  return (
    <section
      ref={rootRef}
      className="relative min-h-dvh w-full grain scanlines"
      style={{
        backgroundColor: 'var(--flood-bg)',
        color: 'var(--flood-fg)',
      }}
    >
      {/* Top status bar */}
      <header
        data-reveal
        className="relative z-10 flex items-start justify-between px-6 sm:px-10 lg:px-16 pt-6"
        style={{ color: 'var(--flood-meta)' }}
      >
        <div className="flex items-center gap-3">
          <svg
            width="22"
            height="22"
            viewBox="0 0 64 64"
            className="shrink-0"
            aria-hidden="true"
          >
            <path
              d="M14 33 L27 46 L51 18"
              stroke="currentColor"
              strokeWidth="6"
              fill="none"
              strokeLinecap="square"
            />
          </svg>
          <div className="font-mono text-[10px] uppercase tracking-[0.32em]">
            <span className="font-display italic text-base normal-case tracking-normal">
              greenlight
            </span>
            <span className="mx-3 opacity-50">//</span>
            <span>verify before you paste</span>
          </div>
        </div>
        <div className="hidden sm:flex flex-col items-end gap-1 font-mono text-[10px] uppercase tracking-[0.28em]">
          <span>OFFLINE-FIRST · NOTHING LEAVES THIS PAGE</span>
          <span className="opacity-60">v0.1 · {verdict.findings.length} findings</span>
        </div>
      </header>

      {/* Decorative barcode strip — adds editorial feel */}
      <div
        data-reveal
        aria-hidden="true"
        className="barcode mt-4 mx-6 sm:mx-10 lg:mx-16 h-2 opacity-30 relative z-10"
        style={{ color: 'var(--flood-meta)' }}
      />

      {/* Main grid — input upper-left, verdict bottom-right (asymmetric, breaking the rule) */}
      <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 px-6 sm:px-10 lg:px-16 pt-10 lg:pt-14 pb-16 lg:pb-24">
        {/* Input column */}
        <div data-reveal className="lg:col-span-7 flex flex-col gap-4">
          <div className="flex items-center justify-between gap-3">
            <span
              className="font-mono text-[10px] uppercase tracking-[0.32em]"
              style={{ color: 'var(--flood-meta)' }}
            >
              <span className="inline-block w-2 h-2 mr-2 align-middle" style={{ backgroundColor: 'var(--flood-fg)' }} />
              {isPending ? 'scanning…' : 'paste here'}
            </span>
            <KindToggle value={kindOverride} onChange={setKindOverride} />
          </div>

          <div
            className="relative border-2 transition-colors"
            style={{ borderColor: 'color-mix(in srgb, var(--flood-fg) 22%, transparent)' }}
          >
            {/* Scan sweep overlay */}
            <div
              ref={scanRef}
              aria-hidden="true"
              className="pointer-events-none absolute inset-y-0 -left-2 w-16 z-10"
              style={{
                background: `linear-gradient(90deg, transparent 0%, color-mix(in srgb, var(--flood-fg) 14%, transparent) 50%, transparent 100%)`,
                mixBlendMode: 'screen',
              }}
            />
            <textarea
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="paste a shell command, URL, or config…"
              aria-label="Input to validate"
              className="block w-full min-h-[260px] p-6 font-mono text-base sm:text-lg leading-relaxed resize-y placeholder:opacity-40"
              style={{ color: 'var(--flood-fg)' }}
            />
            {/* Token-counter style readout */}
            <div
              className="flex items-center justify-between px-6 py-2 text-[10px] uppercase tracking-[0.32em] font-mono border-t"
              style={{
                borderColor: 'color-mix(in srgb, var(--flood-fg) 14%, transparent)',
                color: 'var(--flood-meta)',
              }}
            >
              <span>kind = {kindOverride === 'auto' ? `auto · ${verdict.kind}` : kindOverride}</span>
              <span>{input.length} chars · {input ? input.split(/\r?\n/).length : 0} lines</span>
            </div>
          </div>

          {/* Findings column lives below input on small screens, also visible here for medium-priority */}
          {verdict.findings.length > 0 && (
            <div className="mt-2 space-y-3">
              {verdict.findings.map((f, i) => (
                <FindingCard
                  key={`${f.ruleId}::${f.span?.[0] ?? ''}::${f.span?.[1] ?? ''}::${i}`}
                  finding={f}
                />
              ))}
            </div>
          )}

          {hasInput && verdict.findings.length === 0 && verdict.severity === 'allow' && (
            <div
              data-finding
              className="mt-2 px-5 py-4 border"
              style={{ borderColor: 'color-mix(in srgb, var(--flood-fg) 22%, transparent)' }}
            >
              <p
                className="font-mono text-[11px] uppercase tracking-[0.28em] mb-1"
                style={{ color: 'var(--flood-meta)' }}
              >
                clear / no rules fired
              </p>
              <p className="font-display italic text-2xl">
                {detailFor('allow', 0, true)}
              </p>
            </div>
          )}
        </div>

        {/* Verdict column — the centerpiece */}
        <aside data-reveal className="lg:col-span-5 flex flex-col gap-6 lg:items-end lg:text-right">
          <div
            className="font-mono text-[10px] uppercase tracking-[0.32em]"
            style={{ color: 'var(--flood-meta)' }}
          >
            <span className="inline-block w-2 h-2 mr-2 align-middle" style={{ backgroundColor: 'var(--flood-fg)' }} />
            verdict
          </div>

          <div className="lg:-mr-2">
            <VerdictWord severity={verdict.severity} hasInput={hasInput} />
          </div>

          <div className="max-w-md">
            <p
              className="font-mono text-[11px] uppercase tracking-[0.32em] mb-2"
              style={{ color: 'var(--flood-meta)' }}
            >
              {hasInput ? VERDICT_LABEL[verdict.severity] : 'AWAITING INPUT'}
            </p>
            <p className="font-display italic text-2xl leading-tight text-balance">
              {detailFor(verdict.severity, verdict.findings.length, hasInput)}
            </p>
          </div>

          {hasInput && verdict.severity === 'allow' && (
            <button
              type="button"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(input);
                  setCopyState('copied');
                } catch {
                  setCopyState('failed');
                }
                setTimeout(() => setCopyState('idle'), 1500);
              }}
              className="px-5 py-3 font-mono text-[11px] uppercase tracking-[0.28em] border"
              style={{
                borderColor: 'color-mix(in srgb, var(--flood-fg) 60%, transparent)',
                backgroundColor:
                  copyState === 'copied'
                    ? 'var(--flood-fg)'
                    : 'color-mix(in srgb, var(--flood-fg) 6%, transparent)',
                color: copyState === 'copied' ? 'var(--flood-bg)' : 'var(--flood-fg)',
                transition: 'background-color 200ms ease, color 200ms ease',
              }}
            >
              {copyState === 'copied'
                ? 'copied ✓'
                : copyState === 'failed'
                ? 'copy failed — try again'
                : 'copy verified input ↗'}
            </button>
          )}
        </aside>
      </div>

      {/* Bottom decorative ruler */}
      <div className="relative z-10 px-6 sm:px-10 lg:px-16 pb-6">
        <div
          className="h-px"
          style={{ backgroundColor: 'color-mix(in srgb, var(--flood-fg) 20%, transparent)' }}
        />
        <div
          className="flex items-center justify-between mt-3 font-mono text-[10px] uppercase tracking-[0.32em]"
          style={{ color: 'var(--flood-meta)' }}
        >
          <span>checkpoint::greenlight</span>
          <span>scroll for engine internals ↓</span>
        </div>
      </div>
    </section>
  );
}
