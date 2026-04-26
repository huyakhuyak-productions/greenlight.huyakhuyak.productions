import type { KindOverride } from '../hooks/useValidator';

const OPTIONS: ReadonlyArray<{ value: KindOverride; label: string }> = [
  { value: 'auto', label: 'auto' },
  { value: 'command', label: 'command' },
  { value: 'url', label: 'url' },
  { value: 'config', label: 'config' },
];

interface KindToggleProps {
  value: KindOverride;
  onChange: (next: KindOverride) => void;
}

export function KindToggle({ value, onChange }: KindToggleProps) {
  return (
    <div
      role="radiogroup"
      aria-label="Force input kind"
      className="inline-flex items-center gap-0 border"
      style={{
        borderColor: 'color-mix(in srgb, var(--flood-fg) 20%, transparent)',
        backgroundColor: 'color-mix(in srgb, var(--flood-fg) 4%, transparent)',
      }}
    >
      {OPTIONS.map((opt, i) => {
        const active = value === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(opt.value)}
            className="px-3 py-1.5 text-[10px] uppercase tracking-[0.18em] font-mono"
            style={{
              borderLeft:
                i === 0 ? 'none' : '1px solid color-mix(in srgb, var(--flood-fg) 14%, transparent)',
              backgroundColor: active ? 'var(--flood-fg)' : 'transparent',
              color: active
                ? 'var(--flood-bg)'
                : 'color-mix(in srgb, var(--flood-fg) 70%, transparent)',
              transition: 'background-color 200ms ease, color 200ms ease',
            }}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
