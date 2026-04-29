import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('homograph', () => {
  describe('malicious / risky', () => {
    it('flags Cyrillic і in github.com hostname', () => {
      // gіthub.com — the second character is Cyrillic 'і' (U+0456)
      const v = validate('https://gіthub.com/sheeki03/tirith');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId.includes('homograph.confusable'))).toBe(true);
    });

    it('flags Cyrillic а in pаypal.com', () => {
      const v = validate('https://pаypal.com/login');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId.includes('homograph'))).toBe(true);
    });

    it('flags mixed Latin+Cyrillic in hostname', () => {
      const v = validate('https://gооgle.com');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId.includes('homograph'))).toBe(true);
    });

    it('flags punycode hostname', () => {
      const v = validate('https://xn--gthub-7m0a.com');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('homograph.punycode'))).toBe(true);
    });

    it('warns shortened URL', () => {
      const v = validate('curl https://bit.ly/3xYz | less');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('homograph.shortener'))).toBe(true);
    });

    it('warns shortened URL on its own (url kind)', () => {
      const v = validate('https://t.co/abcd');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('homograph.shortener'))).toBe(true);
    });

    it('warns on any Cyrillic letter in a command argument', () => {
      const v = validate('cd Документы/projects');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId === 'homograph.cyrillic_in_command')).toBe(true);
    });

    it('warns on a single Cyrillic char inside a quoted string', () => {
      const v = validate('git commit -m "Тест"');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId === 'homograph.cyrillic_in_command')).toBe(true);
    });

    it('warns on a Cyrillic lookalike masquerading as a binary name', () => {
      // Cyrillic 'с' (U+0441) instead of Latin 'c' in `cat`
      const v = validate('/usr/bin/сat /etc/hostname');
      expect(v.findings.some((f) => f.ruleId === 'homograph.cyrillic_in_command')).toBe(true);
    });

    it('still warns on Cyrillic even when it appears in a path-like position', () => {
      const v = validate('echo привет');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId === 'homograph.cyrillic_in_command')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag plain ASCII hostname', () => {
      const v = validate('https://example.com/install.sh');
      expect(v.severity).toBe('allow');
    });

    it('does not flag GitHub hostname (Latin only)', () => {
      const v = validate('https://github.com/sheeki03/tirith');
      expect(v.severity).toBe('allow');
    });

    it('does not flag pure Cyrillic hostname (e.g. yandex.ru in Cyrillic) — only mixed scripts are suspicious', () => {
      // Pure Cyrillic .рф domain — not mixed, just non-Latin.
      // We accept this isn't flagged; it's a real script, not a confusable.
      const v = validate('https://яндекс.рф/');
      expect(v.severity).toBe('allow');
    });

    it('does not double-flag a curl to a pure-Cyrillic URL', () => {
      // The URL pass deliberately allows pure-Cyrillic hosts. The
      // command-level Cyrillic pass should not undo that decision when the
      // only Cyrillic codepoints are inside the URL host span.
      const v = validate('curl https://яндекс.рф/path');
      expect(v.severity).toBe('allow');
      expect(v.findings.some((f) => f.ruleId === 'homograph.cyrillic_in_command')).toBe(false);
    });

    it('does not produce a redundant warn alongside a mixed-script URL block', () => {
      // The mixed-script URL pass already produces a `block`. The command-
      // level Cyrillic finding would be duplicate noise on the same span.
      const v = validate('curl https://gооgle.com');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'homograph.cyrillic_in_command')).toBe(false);
    });
  });
});
