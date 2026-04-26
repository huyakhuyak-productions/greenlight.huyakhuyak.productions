import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('insecure-transport', () => {
  describe('malicious / risky', () => {
    it('flags curl -k', () => {
      const v = validate('curl -k https://example.com/install.sh');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('insecure_transport.tls_disabled'))).toBe(true);
    });

    it('flags curl --insecure', () => {
      const v = validate('curl --insecure https://example.com/x');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('insecure_transport.tls_disabled'))).toBe(true);
    });

    it('flags wget --no-check-certificate', () => {
      const v = validate('wget --no-check-certificate https://example.com/x');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('insecure_transport.tls_disabled'))).toBe(true);
    });

    it('flags NODE_TLS_REJECT_UNAUTHORIZED=0', () => {
      const v = validate('NODE_TLS_REJECT_UNAUTHORIZED=0 npm install foo');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('insecure_transport.node_tls_reject'))).toBe(true);
    });

    it('blocks plain http piped to bash', () => {
      const v = validate('curl http://example.com/install.sh | bash');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId.includes('insecure_transport.http_pipe_shell'))).toBe(true);
    });

    it('warns plain http to wget without TLS', () => {
      const v = validate('wget http://example.com/script.sh');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId.includes('insecure_transport.plain_http'))).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag https curl', () => {
      const v = validate('curl https://example.com/api');
      expect(v.severity).toBe('allow');
    });

    it('does not flag a plain http URL on its own (url kind)', () => {
      // A URL by itself isn't a fetch — only homograph rule would have an opinion later
      const v = validate('http://example.com');
      expect(v.severity).toBe('allow');
    });

    it('does not flag curl over https without -k', () => {
      const v = validate('curl https://api.example.com/v1/users');
      expect(v.severity).toBe('allow');
    });
  });
});
