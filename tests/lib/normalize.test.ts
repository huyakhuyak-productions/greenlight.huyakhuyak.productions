import { describe, it, expect } from 'vitest';
import { normalizePaste } from '../../src/lib/normalize';

describe('normalizePaste', () => {
  it('strips trailing spaces and tabs from each line', () => {
    expect(normalizePaste('echo hi   \n   \t\nls\t\t')).toBe('echo hi\n\nls');
  });

  it('normalizes CRLF and bare CR to LF', () => {
    expect(normalizePaste('a\r\nb\rc\nd')).toBe('a\nb\nc\nd');
  });

  it('collapses three or more consecutive blank lines into one', () => {
    expect(normalizePaste('a\n\n\n\n\nb')).toBe('a\n\nb');
  });

  it('preserves a single blank line between commands', () => {
    expect(normalizePaste('a\n\nb')).toBe('a\n\nb');
  });

  it('trims outer ASCII whitespace', () => {
    expect(normalizePaste('   \n\n  curl …  \n\n  ')).toBe('curl …');
  });

  it('is a no-op on already-clean single-line input', () => {
    expect(normalizePaste('curl https://example.com')).toBe('curl https://example.com');
  });

  it('preserves intentional indentation inside lines', () => {
    expect(normalizePaste('if x:\n    print("hi")')).toBe('if x:\n    print("hi")');
  });

  it('preserves a U+FEFF BOM at the start (terminal-injection threat)', () => {
    // ﻿ is matched by JS \s but the terminal-injection rule looks for it
    // as a zero-width threat. The normalizer must not silently strip it.
    const withBom = '﻿curl https://example.com';
    expect(normalizePaste(withBom)).toBe(withBom);
  });

  it('preserves zero-width spaces (U+200B) anywhere', () => {
    const withZwsp = 'cur​l https://example.com';
    expect(normalizePaste(withZwsp)).toBe(withZwsp);
  });

  it('preserves non-breaking spaces (U+00A0) — they can mask shell args', () => {
    const withNbsp = 'curl https://example.com';
    expect(normalizePaste(withNbsp)).toBe(withNbsp);
  });

  it('handles the screenshot case: trailing tabs + multi-blank-line wreckage', () => {
    const messy = '# download\t\t\n\n\n\nwget x\n\n\n\n# run\n\n\nbash y\n   ';
    expect(normalizePaste(messy)).toBe('# download\n\nwget x\n\n# run\n\nbash y');
  });

  it('returns empty string for whitespace-only input', () => {
    expect(normalizePaste('   \n\n\t  \n  ')).toBe('');
  });
});
