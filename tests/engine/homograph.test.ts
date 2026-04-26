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
      // Either allow or warn (TLD heuristic) is acceptable; we just ensure no block.
      expect(v.severity).not.toBe('block');
    });
  });
});
