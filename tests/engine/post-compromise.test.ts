import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('post-compromise', () => {
  describe('container escape', () => {
    it('flags docker run --privileged', () => {
      const v = validate('docker run --privileged --rm alpine sh');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.container_escape')).toBe(true);
    });

    it('flags --cap-add=ALL', () => {
      const v = validate('docker run --rm --cap-add=ALL alpine sh');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.container_escape')).toBe(true);
    });

    it('flags host root mount via -v /:/host', () => {
      const v = validate('docker run --rm -v /:/host alpine chroot /host');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.container_escape')).toBe(true);
    });

    it('flags host root mount via --volume', () => {
      const v = validate('docker run --rm --volume=/:/mnt alpine sh');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.container_escape')).toBe(true);
    });

    it('flags --pid=host', () => {
      const v = validate('docker run --rm --pid=host alpine ps auxf');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.container_escape')).toBe(true);
    });
  });

  describe('process memory', () => {
    it('flags reading /proc/<pid>/mem', () => {
      const v = validate('cat /proc/1234/mem');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.process_memory_dump')).toBe(true);
    });

    it('flags gcore', () => {
      const v = validate('gcore -o /tmp/dump 1234');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.process_memory_dump')).toBe(true);
    });

    it('flags procdump', () => {
      const v = validate('procdump -ma lsass.exe lsass.dmp');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.process_memory_dump')).toBe(true);
    });
  });

  describe('credential reads', () => {
    it('flags reading ~/.aws/credentials', () => {
      const v = validate('cat ~/.aws/credentials');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.credential_file_read')).toBe(true);
    });

    it('flags reading ~/.ssh/id_rsa', () => {
      const v = validate('cat ~/.ssh/id_rsa');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.credential_file_read')).toBe(true);
    });

    it('flags reading ~/.kube/config', () => {
      const v = validate('cat ~/.kube/config');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.credential_file_read')).toBe(true);
    });

    it('flags /etc/shadow read', () => {
      const v = validate('cat /etc/shadow');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.shadow_read')).toBe(true);
    });

    it('flags getent shadow', () => {
      const v = validate('getent shadow');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.shadow_read')).toBe(true);
    });
  });

  describe('credential sweeps', () => {
    it('warns on find / with -name "*.pem"', () => {
      const v = validate('find / -name "*.pem" 2>/dev/null');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.credential_sweep')).toBe(true);
    });

    it('warns on find ~ for id_*', () => {
      const v = validate('find ~ -name "id_*"');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.credential_sweep')).toBe(true);
    });

    it('warns on grep -r "password" /', () => {
      const v = validate('grep -ri "password" /etc/');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.credential_sweep')).toBe(true);
    });

    it('warns on grep -r "api_key"', () => {
      const v = validate('grep -r "api_key" /var/');
      expect(v.findings.some((f) => f.ruleId === 'post_compromise.credential_sweep')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag a normal docker run', () => {
      const v = validate('docker run --rm -p 8080:80 nginx');
      expect(v.severity).toBe('allow');
    });

    it('does not flag cat of a normal file', () => {
      const v = validate('cat README.md');
      expect(v.severity).toBe('allow');
    });

    it('does not flag find for source files', () => {
      const v = validate('find . -name "*.ts"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag grep in a project directory', () => {
      const v = validate('grep -r "TODO" src/');
      expect(v.severity).toBe('allow');
    });

    it('does not flag reading /proc/cpuinfo', () => {
      const v = validate('cat /proc/cpuinfo');
      expect(v.severity).toBe('allow');
    });
  });
});
