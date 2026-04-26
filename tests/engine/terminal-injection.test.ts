import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

const expectFinding = (input: string, ruleSubstring: string, sev: 'block' | 'warn' = 'block') => {
  const v = validate(input);
  expect(v.severity, `expected ${sev} for input`).toBe(sev);
  expect(v.findings.some((f) => f.ruleId.includes(ruleSubstring))).toBe(true);
};

describe('terminal-injection', () => {
  describe('malicious', () => {
    it('flags ANSI CSI escape', () => {
      expectFinding(`echo "\x1b[2J\x1b[Hcleared"`, 'terminal_injection.ansi_escape');
    });

    it('flags bidi RIGHT-TO-LEFT OVERRIDE (U+202E)', () => {
      // "evil‮.txt" → would render reversed in terminals
      expectFinding('rm ‮txt.evil‬', 'terminal_injection.bidi_override');
    });

    it('flags zero-width joiner inside a hostname', () => {
      expectFinding('curl https://gith​ub.com/install.sh', 'terminal_injection.zero_width');
    });

    it('flags BYTE ORDER MARK in middle of input', () => {
      expectFinding('rm ﻿-rf /tmp/x', 'terminal_injection.zero_width');
    });

    it('flags Unicode tag chars (U+E0000–U+E007F)', () => {
      expectFinding('echo hello\u{E0041}\u{E0042}', 'terminal_injection.unicode_tag');
    });

    it('flags raw OSC sequence', () => {
      expectFinding('echo "\x1b]0;evil\x07"', 'terminal_injection.ansi_escape');
    });
  });

  describe('benign', () => {
    it('does not flag plain ASCII', () => {
      const v = validate('echo hello world');
      expect(v.severity).toBe('allow');
    });

    it('does not flag normal Unicode (emoji)', () => {
      const v = validate('echo hello 🌍');
      expect(v.severity).toBe('allow');
    });

    it('does not flag accented Latin characters', () => {
      const v = validate('echo café');
      expect(v.severity).toBe('allow');
    });

    it('does not flag CJK characters', () => {
      const v = validate('echo 你好');
      expect(v.severity).toBe('allow');
    });
  });
});
