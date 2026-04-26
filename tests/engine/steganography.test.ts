import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('steganography', () => {
  describe('malicious / hidden payload', () => {
    it('flags Mongolian Vowel Separator (U+180E)', () => {
      const v = validate('npm install lodash᠎');
      expect(v.findings.some((f) => f.category === 'steganography')).toBe(true);
    });

    it('flags Hangul Filler (U+3164)', () => {
      const v = validate('echo helloㅤworld');
      expect(v.findings.some((f) => f.category === 'steganography')).toBe(true);
    });

    it('flags Hangul Choseong/Jungseong Fillers (U+115F, U+1160)', () => {
      const v = validate('fooᅟᅠbar');
      expect(v.findings.some((f) => f.category === 'steganography')).toBe(true);
    });

    it('flags Soft Hyphen (U+00AD)', () => {
      const v = validate('install­package');
      expect(v.findings.some((f) => f.category === 'steganography')).toBe(true);
    });

    it('flags Variation Selectors U+FE00 (non-emoji presentation)', () => {
      const v = validate('curl example.com\u{FE00}');
      expect(v.findings.some((f) => f.category === 'steganography')).toBe(true);
    });

    it('flags Variation Selectors Supplement (U+E0100)', () => {
      const v = validate('payload\u{E0100}');
      expect(v.findings.some((f) => f.category === 'steganography')).toBe(true);
    });

    it('escalates to block when many invisibles cluster (likely payload)', () => {
      const cluster = '᠎ㅤᅟᅠ­᠎ㅤᅟᅠ­';
      const v = validate(`hello${cluster}world`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'steganography')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag a plain ASCII command', () => {
      const v = validate('ls -la');
      expect(v.severity).toBe('allow');
    });

    it('does not flag plain Korean text', () => {
      const v = validate('echo "안녕하세요"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag plain emoji (not a variation selector by itself)', () => {
      // bare 😀 — no VS-16 attached
      const v = validate('echo "Hello 😀"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag emoji with VS-16 (U+FE0F) presentation selector', () => {
      // ❤️ ⚠️ ✅ all carry an implicit U+FE0F on iOS/macOS keyboards.
      // Flagging this would warn on every commit message and chat paste.
      const v = validate('echo "I ❤️ this ⚠️ thing ✅"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag many VS-16 emoji as a "cluster"', () => {
      const v = validate('PR review: ❤️❤️ ⚠️⚠️ ✅✅ — looks good');
      expect(v.severity).toBe('allow');
    });
  });
});
