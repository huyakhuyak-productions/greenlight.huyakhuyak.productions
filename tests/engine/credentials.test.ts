import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('credentials', () => {
  describe('malicious / leaked credentials', () => {
    it('flags an AWS access key (AKIA…)', () => {
      const v = validate('export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
      expect(v.severity === 'block' || v.severity === 'warn').toBe(true);
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags an AWS temporary access key (ASIA…)', () => {
      const v = validate('AWS_ACCESS_KEY=ASIA1234567890ABCDEF curl https://example.com/');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a GitHub personal access token (ghp_…)', () => {
      const v = validate('git config --global token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a GitHub fine-grained PAT (github_pat_)', () => {
      const v = validate(
        'export GH_TOKEN=github_pat_11ABCDEFG0aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkLmNoPqRsTuVwXyZ12',
      );
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a Slack bot token (xoxb-…)', () => {
      const v = validate('SLACK_TOKEN=xoxb-EXAMPLE000-EXAMPLE0000-EXAMPLEEXAMPLEEXAMPLEEXAM');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a Stripe live secret key', () => {
      const v = validate('STRIPE_KEY=sk_live_EXAMPLEEXAMPLEEXAMPLE');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a PEM private key header', () => {
      const v = validate(
        '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
      );
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags an OpenSSH private key header', () => {
      const v = validate('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags an AWS key butted up against extra alnum chars (no \\b)', () => {
      // 16 trailing chars + a 17th alnum directly after — would defeat \b.
      const v = validate('AWSKey=AKIAIOSFODNN7EXAMPLEEXTRA');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a Google API key butted up against extra alnum chars', () => {
      const v = validate('KEY=AIzaSyC-AbCdEfGhIjKlMnOpQrStUvWxYz12345EXTRA');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a Slack app-level token (xapp-)', () => {
      const v = validate('SLACK_APP=xapp-1-A012345-12345-AbCdEfGhIjKlMnOpQrStUvWxYz');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });

    it('flags a Stripe webhook secret (whsec_)', () => {
      const v = validate('STRIPE_WEBHOOK=whsec_AbCdEfGhIjKlMnOpQrStUvWxYz12345678');
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag a plain bash export of PATH', () => {
      const v = validate('export PATH=/usr/local/bin:$PATH');
      expect(v.severity).toBe('allow');
    });

    it('does not flag plain ls', () => {
      const v = validate('ls -la');
      expect(v.severity).toBe('allow');
    });

    it('does not flag the literal token "AKIA" in prose / placeholder', () => {
      const v = validate('# AKIA tokens look like this: AKIA...');
      // 4-char fragment without 16 trailing alphanumerics → not a real key
      expect(v.findings.some((f) => f.category === 'credentials')).toBe(false);
    });

    it('does not flag a normal hex sha (40 chars, not a known prefix)', () => {
      const v = validate('git checkout 0123456789abcdef0123456789abcdef01234567');
      expect(v.severity).toBe('allow');
    });
  });
});
