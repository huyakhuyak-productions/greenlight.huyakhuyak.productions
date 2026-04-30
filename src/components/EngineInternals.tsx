import { useLayoutEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

type Step = {
  index: string;
  label: string;
  title: string;
  body: string;
  meta: string;
};

const STEPS: ReadonlyArray<Step> = [
  {
    index: '01',
    label: 'classify',
    title: 'is it a command, a URL, or a config?',
    body: 'A tiny classifier sniffs the input shape — a single URL, a multi-line config blob, or a shell snippet. The kind decides which rules fire.',
    meta: 'classify(input) → command | url | config',
  },
  {
    index: '02',
    label: 'run rules',
    title: 'fan out across fifteen detectors',
    body: 'Every applicable rule runs against your input. Each rule is a pure function returning findings — no IO, no network, deterministic.',
    meta: 'rules.flatMap(r => r.run(input, kind))',
  },
  {
    index: '03',
    label: 'verdict',
    title: 'the worst finding wins',
    body: 'Severities collapse: a single block beats any number of warns; a single warn beats a clean run. The verdict is the upper bound, not an average.',
    meta: 'severity = max(allow, warn, block)',
  },
];

type CategoryCard = {
  slug: string;
  name: string;
  blurb: string;
  tier: 1 | 2 | 3 | 4;
};

const CATEGORIES: ReadonlyArray<CategoryCard> = [
  { slug: 'pipe-to-shell', name: 'pipe to shell', blurb: 'curl … | bash, process substitution, fetched-and-executed code.', tier: 1 },
  { slug: 'base64-exec', name: 'base64 exec', blurb: 'decoded payloads piped into an interpreter — bash, powershell, python.', tier: 1 },
  { slug: 'terminal-injection', name: 'terminal injection', blurb: 'ANSI escapes, bidi overrides, zero-width chars, Unicode tag chars.', tier: 1 },
  { slug: 'insecure-transport', name: 'insecure transport', blurb: '--insecure, NODE_TLS_REJECT_UNAUTHORIZED=0, plain http piped to a shell.', tier: 1 },
  { slug: 'homograph', name: 'homograph', blurb: 'Cyrillic/Greek lookalikes, mixed-script hosts, punycode, confusable TLDs.', tier: 1 },
  { slug: 'exfiltration', name: 'exfiltration', blurb: 'POST of credential files, env-var uploads, --data @~/.ssh/id_rsa.', tier: 2 },
  { slug: 'credentials', name: 'credentials', blurb: 'AWS keys, GitHub PATs, private-key headers, high-entropy strings.', tier: 2 },
  { slug: 'command-safety', name: 'command safety', blurb: 'shell rc overwrites, rm -rf /, IMDS metadata reads, traversal extracts.', tier: 2 },
  { slug: 'steganography', name: 'steganography', blurb: 'invisible whitespace variants, Hangul fillers, Mongolian vowel separators.', tier: 2 },
  { slug: 'config-injection', name: 'config injection', blurb: 'shell metacharacters in args, prompt-injection keywords in agent configs.', tier: 3 },
  { slug: 'ecosystem', name: 'ecosystem', blurb: 'typosquats, untrusted registries, URL-based pip / npm installs.', tier: 3 },
  { slug: 'environment', name: 'environment', blurb: 'LD_PRELOAD, PYTHONSTARTUP, proxy exports, shebang hijacking.', tier: 3 },
  { slug: 'code-scan', name: 'code scan', blurb: 'decoder-into-executor chains, dynamic imports, exec-of-decoded payloads.', tier: 4 },
  { slug: 'post-compromise', name: 'post-compromise', blurb: 'docker privilege escalation, /proc memory reads, credential file sweeps.', tier: 4 },
  { slug: 'path-analysis', name: 'path analysis', blurb: 'directory traversal, encoded ../, null bytes, non-ASCII Unix paths.', tier: 4 },
];

const TIER_LABEL: Record<CategoryCard['tier'], string> = {
  1: 'tier i',
  2: 'tier ii',
  3: 'tier iii',
  4: 'tier iv',
};

export function EngineInternals() {
  const rootRef = useRef<HTMLElement>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  const stepsRef = useRef<HTMLDivElement>(null);
  const progressRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);

  // Pinned three-step crossfade — the centerpiece of this section.
  // We pin the stage for ~3x viewport height, then scrub a timeline that
  // walks the active step from 1 → 2 → 3 as the user scrolls. Falling off
  // the bottom of the pin releases the page back to normal flow.
  useLayoutEffect(() => {
    const root = rootRef.current;
    const stage = stageRef.current;
    const stepsEl = stepsRef.current;
    const progress = progressRef.current;
    if (!root || !stage || !stepsEl || !progress) return;

    const stepNodes = gsap.utils.toArray<HTMLElement>('[data-step]', stepsEl);
    if (stepNodes.length === 0) return;

    const ctx = gsap.context(() => {
      // Seed: only step 1 visible.
      gsap.set(stepNodes, { opacity: 0, y: 40 });
      gsap.set(stepNodes[0], { opacity: 1, y: 0 });
      gsap.set(progress, { scaleX: 1 / stepNodes.length, transformOrigin: 'left center' });

      const tl = gsap.timeline({
        scrollTrigger: {
          trigger: stage,
          start: 'top top',
          end: () => `+=${stepNodes.length * 90}%`,
          scrub: 0.6,
          pin: stage,
          pinSpacing: true,
          anticipatePin: 1,
          invalidateOnRefresh: true,
        },
      });

      stepNodes.forEach((node, i) => {
        if (i === 0) return;
        const prev = stepNodes[i - 1];
        const segment = `+=${1}`;
        tl.to(prev, { opacity: 0, y: -40, duration: 1, ease: 'power2.inOut' }, segment)
          .fromTo(
            node,
            { opacity: 0, y: 40 },
            { opacity: 1, y: 0, duration: 1, ease: 'power2.inOut' },
            '<',
          )
          .to(
            progress,
            {
              scaleX: (i + 1) / stepNodes.length,
              duration: 1,
              ease: 'power2.inOut',
            },
            '<',
          );
      });
    }, root);

    return () => {
      ctx.revert();
    };
  }, []);

  // Category grid — staggered reveal as it enters the viewport. No pin, no
  // scrub; this is a one-shot batch animation triggered once.
  useLayoutEffect(() => {
    const grid = gridRef.current;
    if (!grid) return;

    const ctx = gsap.context(() => {
      const cards = gsap.utils.toArray<HTMLElement>('[data-category]', grid);
      if (cards.length === 0) return;
      gsap.set(cards, { opacity: 0, y: 32 });
      ScrollTrigger.batch(cards, {
        start: 'top 88%',
        once: true,
        onEnter: (batch) => {
          gsap.to(batch, {
            opacity: 1,
            y: 0,
            duration: 0.7,
            ease: 'expo.out',
            stagger: 0.05,
            overwrite: 'auto',
          });
        },
      });
    }, grid);

    return () => {
      ctx.revert();
    };
  }, []);

  return (
    <section
      ref={rootRef}
      aria-label="How greenlight works"
      className="relative w-full"
      style={{
        backgroundColor: 'var(--color-ink)',
        color: 'var(--color-bone)',
      }}
    >
      {/* Section eyebrow */}
      <div className="px-6 sm:px-10 lg:px-16 pt-20 lg:pt-32 pb-10 lg:pb-16 max-w-[1400px] mx-auto">
        <div
          className="font-mono text-[10px] uppercase tracking-[0.32em]"
          style={{ color: 'var(--color-bone-2)' }}
        >
          <span className="inline-block w-2 h-2 mr-2 align-middle" style={{ backgroundColor: 'var(--color-poison)' }} />
          engine internals · how greenlight works
        </div>
        <h2 className="font-display italic text-[clamp(3rem,9vw,9rem)] leading-[0.92] mt-6 max-w-[18ch]">
          three steps,<br />zero network calls.
        </h2>
        <p
          className="font-mono text-sm sm:text-base leading-relaxed mt-8 max-w-[60ch]"
          style={{ color: 'var(--color-bone-2)' }}
        >
          Greenlight is a static rules engine that runs entirely in your browser. Your paste stays on the page — no telemetry, no analytics, no server. The only thing that ever leaves the tab is an explicit click on <em>Scan this script</em>, which fetches the URL the snippet already names so we can run the same engine over its body. Scroll to watch the pipeline.
        </p>
      </div>

      {/* Pinned stage — the three-step crossfade */}
      <div
        ref={stageRef}
        className="relative h-dvh w-full overflow-hidden flex items-center"
        style={{
          backgroundColor: 'var(--color-ink)',
          borderTop: '1px solid var(--color-graphite)',
          borderBottom: '1px solid var(--color-graphite)',
        }}
      >
        {/* Progress bar at the very top of the pinned region */}
        <div
          aria-hidden="true"
          className="absolute top-0 left-0 right-0 h-px"
          style={{ backgroundColor: 'var(--color-graphite)' }}
        >
          <div
            ref={progressRef}
            className="h-full origin-left"
            style={{ backgroundColor: 'var(--color-poison)', width: '100%' }}
          />
        </div>

        {/* Step counter + label, top-left */}
        <div className="absolute top-6 left-6 sm:left-10 lg:left-16 right-6 sm:right-10 lg:right-16 flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.32em]" style={{ color: 'var(--color-bone-2)' }}>
          <span>checkpoint::pipeline</span>
          <span>scrub to advance ↓</span>
        </div>

        {/* Stack of three steps — only one visible at a time, others tweened out.
            CSS Grid stacking: each article occupies cell (1,1), so they overlap
            in place and the grid takes the height of the tallest step. */}
        <div
          ref={stepsRef}
          className="relative w-full px-6 sm:px-10 lg:px-16 max-w-[1400px] mx-auto grid"
          style={{ gridTemplateAreas: '"stack"' }}
        >
          {STEPS.map((step) => (
            <article
              key={step.index}
              data-step
              className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-16 items-start"
              style={{ gridArea: 'stack' }}
            >
              <div className="lg:col-span-5 flex flex-col gap-3">
                <span
                  className="font-mono text-[10px] uppercase tracking-[0.4em]"
                  style={{ color: 'var(--color-bone-2)' }}
                >
                  step
                </span>
                <span
                  className="font-display text-[clamp(8rem,22vw,18rem)] leading-none italic"
                  style={{ color: 'var(--color-poison)' }}
                >
                  {step.index}
                </span>
                <span
                  className="font-mono text-xs uppercase tracking-[0.32em]"
                  style={{ color: 'var(--color-bone)' }}
                >
                  {step.label}
                </span>
              </div>

              <div className="lg:col-span-7 flex flex-col gap-6">
                <h3 className="font-display italic text-[clamp(2rem,5vw,4.25rem)] leading-[1] max-w-[18ch]">
                  {step.title}
                </h3>
                <p
                  className="font-mono text-sm sm:text-base leading-relaxed max-w-[58ch]"
                  style={{ color: 'var(--color-bone-2)' }}
                >
                  {step.body}
                </p>
                <div
                  className="mt-2 inline-flex items-center self-start px-3 py-2 border font-mono text-xs"
                  style={{
                    borderColor: 'color-mix(in srgb, var(--color-bone) 28%, transparent)',
                    color: 'var(--color-bone)',
                    backgroundColor: 'color-mix(in srgb, var(--color-bone) 4%, transparent)',
                  }}
                >
                  <span className="opacity-50 mr-2">$</span>
                  <span>{step.meta}</span>
                </div>
              </div>
            </article>
          ))}
        </div>

        {/* Scanline drift on the pinned region for atmosphere */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage:
              'repeating-linear-gradient(to bottom, transparent 0, transparent 3px, currentColor 3px, currentColor 4px)',
            color: 'var(--color-bone)',
          }}
        />
      </div>

      {/* Category grid — fifteen detection categories */}
      <div className="px-6 sm:px-10 lg:px-16 pt-20 lg:pt-32 pb-10 lg:pb-16 max-w-[1400px] mx-auto">
        <div className="flex items-end justify-between mb-10 gap-6 flex-wrap">
          <div>
            <div
              className="font-mono text-[10px] uppercase tracking-[0.32em] mb-4"
              style={{ color: 'var(--color-bone-2)' }}
            >
              <span className="inline-block w-2 h-2 mr-2 align-middle" style={{ backgroundColor: 'var(--color-poison)' }} />
              detectors · {CATEGORIES.length} categories
            </div>
            <h3 className="font-display italic text-[clamp(2.5rem,6vw,5.5rem)] leading-[0.95] max-w-[20ch]">
              fifteen ways<br />a paste can betray you.
            </h3>
          </div>
          <p
            className="font-mono text-sm leading-relaxed max-w-[40ch]"
            style={{ color: 'var(--color-bone-2)' }}
          >
            Each category is a self-contained TypeScript module — open source, auditable, deterministic. Tiers reflect how often a paste in the wild matches that surface.
          </p>
        </div>

        <div ref={gridRef} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px" style={{ backgroundColor: 'var(--color-graphite)' }}>
          {CATEGORIES.map((cat, i) => (
            <article
              key={cat.slug}
              data-category
              className="group relative p-6 lg:p-8 flex flex-col gap-4 transition-colors"
              style={{
                backgroundColor: 'var(--color-ink)',
              }}
            >
              <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.32em]" style={{ color: 'var(--color-bone-2)' }}>
                <span>{String(i + 1).padStart(2, '0')}</span>
                <span style={{ color: 'var(--color-poison)' }}>{TIER_LABEL[cat.tier]}</span>
              </div>
              <h4 className="font-display italic text-[clamp(1.6rem,2.5vw,2.25rem)] leading-[1.05]" style={{ color: 'var(--color-bone)' }}>
                {cat.name}
              </h4>
              <p
                className="font-mono text-xs sm:text-sm leading-relaxed"
                style={{ color: 'var(--color-bone-2)' }}
              >
                {cat.blurb}
              </p>
              <div
                aria-hidden="true"
                className="mt-auto h-px w-10 transition-all group-hover:w-24"
                style={{ backgroundColor: 'var(--color-poison)' }}
              />
            </article>
          ))}
        </div>
      </div>

      {/* Outro — privacy promise */}
      <div className="px-6 sm:px-10 lg:px-16 pt-10 lg:pt-20 pb-24 lg:pb-32 max-w-[1400px] mx-auto">
        <div
          className="h-px mb-10"
          style={{ backgroundColor: 'var(--color-graphite)' }}
        />
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-16 items-end">
          <div className="lg:col-span-7">
            <p
              className="font-mono text-[10px] uppercase tracking-[0.32em] mb-4"
              style={{ color: 'var(--color-bone-2)' }}
            >
              the promise
            </p>
            <p className="font-display italic text-[clamp(2rem,4.5vw,3.75rem)] leading-[1.05] max-w-[22ch]">
              your paste never leaves this page.
            </p>
          </div>
          <div className="lg:col-span-5 flex flex-col gap-3 font-mono text-xs uppercase tracking-[0.28em]" style={{ color: 'var(--color-bone-2)' }}>
            <div className="flex items-center justify-between">
              <span>runtime</span>
              <span style={{ color: 'var(--color-bone)' }}>browser only</span>
            </div>
            <div className="h-px" style={{ backgroundColor: 'var(--color-graphite)' }} />
            <div className="flex items-center justify-between">
              <span>network</span>
              <span style={{ color: 'var(--color-bone)' }}>click only</span>
            </div>
            <div className="h-px" style={{ backgroundColor: 'var(--color-graphite)' }} />
            <div className="flex items-center justify-between">
              <span>storage</span>
              <span style={{ color: 'var(--color-bone)' }}>none</span>
            </div>
            <div className="h-px" style={{ backgroundColor: 'var(--color-graphite)' }} />
            <div className="flex items-center justify-between">
              <span>license</span>
              <span style={{ color: 'var(--color-bone)' }}>open source</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
