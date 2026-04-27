import { useEffect, useRef } from 'react';
import gsap from 'gsap';
import type { Severity } from '../engine';

const WORDS: Record<Severity, string> = {
  allow: 'safe',
  warn: 'caution',
  block: 'stop',
};

interface VerdictWordProps {
  severity: Severity;
  hasInput: boolean;
}

export function VerdictWord({ severity, hasInput }: VerdictWordProps) {
  const ref = useRef<HTMLDivElement>(null);
  const lastSeverityRef = useRef<Severity | null>(null);
  const lastHasInputRef = useRef<boolean>(false);

  useEffect(() => {
    if (!ref.current) return;
    const chars = ref.current.querySelectorAll<HTMLSpanElement>('[data-char]');
    if (chars.length === 0) return;
    const severityChanged = lastSeverityRef.current !== severity;
    const hasInputChanged = lastHasInputRef.current !== hasInput;
    lastSeverityRef.current = severity;
    lastHasInputRef.current = hasInput;

    if (!severityChanged && !hasInputChanged) return;

    const tween = gsap.fromTo(
      chars,
      { yPercent: 100, rotateX: -55, opacity: 0, transformPerspective: 600 },
      {
        yPercent: 0,
        rotateX: 0,
        opacity: 1,
        duration: 0.65,
        ease: 'expo.out',
        stagger: { each: 0.035, from: 'start' },
        overwrite: 'auto',
      },
    );
    return () => {
      tween.kill();
      gsap.set(chars, { clearProps: 'opacity,transform' });
    };
  }, [severity, hasInput]);

  const word = hasInput ? WORDS[severity] : 'paste';

  return (
    <>
      <span className="sr-only" aria-live="polite" aria-atomic="true">
        Verdict: {word}
      </span>
      <div
        ref={ref}
        aria-hidden="true"
        className="font-display italic leading-[0.85] text-balance"
        style={{ fontSize: 'clamp(4.5rem, 22vw, 22rem)' }}
      >
        {/* Padding extends the clip region past each glyph's advance box so
            Instrument Serif's italic side-bearings — the `p` swash (bottom-
            left), the `e` lean (top-right), the long descenders — don't get
            cropped by `overflow-hidden`. The chars start at opacity 0 in the
            GSAP slide-in, so the extra room can't reveal mid-animation. */}
        <span
          className="inline-flex overflow-hidden align-baseline"
          style={{
            paddingBottom: '0.55em',
            paddingLeft: '0.18em',
            paddingRight: '0.22em',
            marginLeft: '-0.18em',
            marginRight: '-0.22em',
          }}
        >
          {word.split('').map((char, i) => (
            <span
              key={`${word}-${i}-${char}`}
              data-char
              className="inline-block will-change-transform"
              style={{ transformOrigin: '50% 100%' }}
            >
              {char}
            </span>
          ))}
        </span>
      </div>
    </>
  );
}
