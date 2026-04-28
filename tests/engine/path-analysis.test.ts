import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('path-analysis', () => {
  describe('directory traversal', () => {
    it('flags ../../../etc/passwd', () => {
      const v = validate('curl http://api.example.com/file?p=../../../etc/passwd');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'path_analysis.traversal_to_sensitive')).toBe(true);
    });

    it('flags ../../home/user/.ssh/id_rsa', () => {
      const v = validate('tar xf x.tar -C ../../home/alice/.ssh/');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'path_analysis.traversal_to_sensitive')).toBe(true);
    });

    it('flags windows backslash traversal', () => {
      const v = validate('..\\..\\..\\windows\\system32\\config\\sam');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'path_analysis.traversal_to_sensitive')).toBe(true);
    });
  });

  describe('encoded traversal', () => {
    it('flags %2e%2e%2f traversal sequences', () => {
      const v = validate('curl https://example.com/%2e%2e%2f%2e%2e%2fetc%2fpasswd');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'path_analysis.encoded_traversal')).toBe(true);
    });

    it('flags double-encoded %252e%252e%252f', () => {
      const v = validate('curl https://example.com/%252e%252e%252fetc');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'path_analysis.encoded_traversal')).toBe(true);
    });
  });

  describe('null byte', () => {
    it('flags any null byte', () => {
      const v = validate('curl https://example.com/file.php\x00.png');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'path_analysis.null_byte')).toBe(true);
    });
  });

  describe('non-ASCII path', () => {
    it('warns on cyrillic letter inside /usr/bin/...', () => {
      // `с` is U+0441 Cyrillic small letter es, looks like Latin `c`.
      const v = validate('/usr/bin/сat /etc/hostname');
      expect(v.findings.some((f) => f.ruleId === 'path_analysis.non_ascii_path')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag normal absolute paths', () => {
      const v = validate('cat /etc/hostname');
      expect(v.severity).toBe('allow');
    });

    it('does not flag a single `..` in a relative import', () => {
      const v = validate('import { x } from "../utils.js"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag a single %2e in a URL', () => {
      const v = validate('https://example.com/file%2etxt');
      expect(v.severity).toBe('allow');
    });

    it('does not flag prose with non-ASCII (no path)', () => {
      const v = validate('this snippet handles café-style names');
      expect(v.severity).toBe('allow');
    });

    it('does not flag a typical npm path with `..`', () => {
      const v = validate('cp ./build/index.js ../dist/');
      expect(v.severity).toBe('allow');
    });
  });
});
