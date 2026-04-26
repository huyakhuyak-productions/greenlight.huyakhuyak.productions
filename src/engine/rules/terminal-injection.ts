import type { Finding, Rule } from '../types';

// ESC (0x1B), BEL (0x07), CSI/OSC starters — actual ANSI control sequences.
// eslint-disable-next-line no-control-regex -- detecting these bytes is the rule's purpose
const ANSI_ESCAPE = /[\x1b\x9b]/;

// Bidirectional formatting controls — used to render text reversed/disguised.
// LRE/RLE/PDF/LRO/RLO and the isolate variants LRI/RLI/FSI/PDI.
const BIDI_CONTROL = /[‪-‮⁦-⁩]/;

// Zero-width and invisible-format characters that don't render but are present.
// ZWSP, ZWNJ, ZWJ, BOM, WORD JOINER.
// eslint-disable-next-line no-irregular-whitespace -- detecting these chars is the rule's purpose
const ZERO_WIDTH = /[​-‍⁠﻿]/;

// Unicode TAG block (U+E0000–U+E007F) — invisible in most terminals/editors,
// recently abused for prompt-injection in AI configs.
const UNICODE_TAG = /[\u{E0000}-\u{E007F}]/u;

function findFirstSpan(input: string, re: RegExp): [number, number] | null {
  const m = input.match(re);
  if (!m || m.index == null) return null;
  return [m.index, m.index + m[0].length];
}

function pickEvidence(input: string, span: [number, number]): string {
  const [a, b] = span;
  const start = Math.max(0, a - 8);
  const end = Math.min(input.length, b + 8);
  return input.slice(start, end);
}

function makeFinding(args: {
  input: string;
  ruleId: string;
  title: string;
  message: string;
  re: RegExp;
}): Finding | null {
  const span = findFirstSpan(args.input, args.re);
  if (!span) return null;
  return {
    ruleId: args.ruleId,
    category: 'terminal-injection',
    severity: 'block',
    title: args.title,
    message: args.message,
    evidence: pickEvidence(args.input, span),
    span,
    remediation:
      'Retype the command by hand instead of pasting. Hidden characters change what the terminal actually receives.',
  };
}

export const terminalInjectionRule: Rule = {
  id: 'terminal_injection',
  category: 'terminal-injection',
  appliesTo: 'any',
  run(input) {
    const findings: Finding[] = [];

    const ansi = makeFinding({
      input,
      re: ANSI_ESCAPE,
      ruleId: 'terminal_injection.ansi_escape',
      title: 'ANSI escape sequence in input',
      message:
        'Raw ANSI escape sequences can clear the screen, reposition the cursor, or rewrite previous lines — making one command appear as another.',
    });
    if (ansi) findings.push(ansi);

    const bidi = makeFinding({
      input,
      re: BIDI_CONTROL,
      ruleId: 'terminal_injection.bidi_override',
      title: 'Bidirectional override character',
      message:
        'Right-to-left override (U+202E) and friends can flip the visual order of characters. The text you see is not the text the shell receives.',
    });
    if (bidi) findings.push(bidi);

    const zw = makeFinding({
      input,
      re: ZERO_WIDTH,
      ruleId: 'terminal_injection.zero_width',
      title: 'Zero-width / invisible character',
      message:
        'Zero-width and BOM characters are invisible. Attackers slip them into hostnames, package names, and command arguments to make benign-looking text resolve to something else.',
    });
    if (zw) findings.push(zw);

    const tag = makeFinding({
      input,
      re: UNICODE_TAG,
      ruleId: 'terminal_injection.unicode_tag',
      title: 'Unicode TAG codepoint',
      message:
        'Unicode TAG characters (U+E0000–U+E007F) are invisible to most terminals and editors. They have been used to smuggle prompt-injection payloads into AI configs and shell commands.',
    });
    if (tag) findings.push(tag);

    return findings;
  },
};
